# views.py - Full updated version
import os
import re
import requests
import pdfkit
import stripe

from collections import namedtuple
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.conf import settings
from django.template.loader import render_to_string, get_template
from django.core.mail import EmailMultiAlternatives, send_mail
from django.core.files.temp import NamedTemporaryFile
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash, get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q, Count, F
from django.http import HttpResponse, JsonResponse, FileResponse, Http404, HttpResponseRedirect
from django.template import RequestContext
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt

# PDF generation using WeasyPrint (preferred here)
from weasyprint import HTML

# Local imports
from .forms import (
    EditProfileForm, UserForm, ProfileForm, RegisterForm, JobForm, ResumeForm, CVUploadForm,
    JobPlanSelectForm, CustomUserCreationForm, ChangeUsernamePasswordForm
)
from .models import (
    JobAlert, ChatMessage, Application, Job, SkillResource, Resume, CVUpload, JobPlan, JobPayment, Profile,
    Notification
)

# Initialize Stripe
stripe.api_key = getattr(settings, "STRIPE_SECRET_KEY", "")

# -------------------------------------------------------------------
# Helper utilities
# -------------------------------------------------------------------

NotificationItem = namedtuple("NotificationItem", ["title", "message", "timestamp", "is_read", "url"])


def _chat_unread_filter_for_user(user):
    """
    Return Q expression for unread chat messages relevant to user (applicant or employer).
    This groups terms properly to avoid precedence issues.
    """
    return (
        Q(application__applicant=user) & ~Q(sender=user)
    ) | (
        Q(application__job__employer=user) & ~Q(sender=user)
    )


def get_unread_messages(user):
    """
    Returns the count of unread chat messages for the given user.
    Fixed logical grouping so OR/AND behave as intended.
    """
    return ChatMessage.objects.filter(is_read=False).filter(_chat_unread_filter_for_user(user)).count()


# -------------------------------------------------------------------
# Notification views
# -------------------------------------------------------------------

@login_required
def notifications(request):
    user = request.user

    notifications_list = []

    # Unread standard notifications
    base_notifications = Notification.objects.filter(user=user, is_read=False).order_by("-timestamp")

    for n in base_notifications:
        url = None
        # detect job_id embedded in text like "(job_id=###)" and make a link
        match = re.search(r"job_id=(\d+)", n.message)
        if match:
            job_id = match.group(1)
            url = reverse("view_applicants") + f"?job_id={job_id}"

        # strip hidden job_id part from message for display
        display_message = n.message.split("(job_id=")[0]

        notifications_list.append(
            NotificationItem(n.title, display_message, n.timestamp, n.is_read, url)
        )

    # Unread chat messages
    unread_chats = ChatMessage.objects.filter(is_read=False).filter(_chat_unread_filter_for_user(user)).order_by("-timestamp")

    for chat in unread_chats:
        # decide URL depending on who owns the application
        if chat.application.applicant == user:
            chat_url = reverse("job_chat", args=[chat.application.id])
        else:
            # employer view of chat: route to employer chat for job, with app_id query param
            chat_url = reverse("employer_chat", args=[chat.application.job.id]) + f"?app_id={chat.application.id}"

        notifications_list.append(
            NotificationItem(
                title=f"New message from {chat.sender.username}",
                message=chat.message,
                timestamp=chat.timestamp,
                is_read=False,
                url=chat_url,
            )
        )

    # sort combined notifications by timestamp (newest first)
    notifications_list.sort(key=lambda n: n.timestamp, reverse=True)

    total_unread = len(notifications_list)

    if not notifications_list:
        messages.info(request, "🔔 You don’t have any notifications yet.")

    context = {
        "notifications": notifications_list,
        "unread_count": total_unread,
        "role": getattr(user, "role", None),
        "title": "My Notifications",
    }
    return render(request, "notifications.html", context)


@login_required
def mark_all_read(request):
    """
    Mark both standard in-app notifications and chat messages as read for the logged-in user.
    """
    user = request.user

    Notification.objects.filter(user=user, is_read=False).update(is_read=True)

    ChatMessage.objects.filter(is_read=False).filter(_chat_unread_filter_for_user(user)).update(is_read=True)

    return redirect("notifications")


# -------------------------------------------------------------------
# Basic auth / user flows
# -------------------------------------------------------------------

User = get_user_model()


def home(request):
    return render(request, "home.html")


def signup_view(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("dashboard")
    else:
        form = CustomUserCreationForm()
    return render(request, "signup.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        identifier = request.POST.get("identifier")
        password = request.POST.get("password")

        # try to locate the user by username / email / phone
        try:
            user_obj = User.objects.get(
                Q(username=identifier) | Q(email=identifier) | Q(phone=identifier)
            )
            username = user_obj.username
        except User.DoesNotExist:
            messages.error(request, "Invalid credentials")
            return render(request, "login.html")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            if user.is_superuser:
                return redirect("admin_dashboard")
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid credentials")

    return render(request, "login.html")


def logout_view(request):
    logout(request)
    return redirect("logout_success")


def logout_success(request):
    return render(request, "logout_success.html")


# -------------------------------------------------------------------
# Dashboard and profile
# -------------------------------------------------------------------

@login_required
def dashboard(request):
    user = request.user

    # counts
    unread_messages_count = get_unread_messages(user)
    notifications_count = Notification.objects.filter(user=user, is_read=False).count()
    total_notifications = notifications_count + unread_messages_count

    # Admin redirect
    if user.is_superuser or getattr(user, "role", None) == "admin":
        return redirect("admin_dashboard")

    # Applicant
    if getattr(user, "role", None) == "applicant":
        applications = Application.objects.filter(applicant=user)
        premium_jobs = applications.filter(job__is_premium=True).count()
        return render(request, "applicant_dashboard.html", {
            "applications": applications,
            "premium_jobs": premium_jobs,
            "notifications_count": total_notifications,
        })

    # Employer
    if getattr(user, "role", None) == "employer":
        posted_jobs_count = Job.objects.filter(employer=user).count()
        active_jobs = Job.objects.filter(employer=user, is_active=True).count()
        applicants_count = Application.objects.filter(job__employer=user).count()
        return render(request, "employer_dashboard.html", {
            "posted_jobs_count": posted_jobs_count,
            "active_jobs": active_jobs,
            "applicants_count": applicants_count,
            "notifications_count": total_notifications,
        })

    # fallback
    return redirect("login")


@login_required
def profile_view(request):
    user = request.user

    # Latest CV
    try:
        user_cv = CVUpload.objects.filter(applicant=user).latest("id")
    except CVUpload.DoesNotExist:
        user_cv = None

    skills_list = []
    if getattr(user, "skills", None):
        skills_list = [s.strip() for s in user.skills.split(",") if s.strip()]

    context = {
        "user": user,
        "user_cv": user_cv,
        "skills": skills_list,
        "profile_picture_url": user.profile_pic.url if getattr(user, "profile_pic", None) else None,
    }
    template_name = "employer_profile.html" if getattr(user, "role", None) == "employer" else "profile.html"
    return render(request, template_name, context)


@login_required
def edit_profile(request):
    # make sure profile exists
    profile, created = Profile.objects.get_or_create(user=request.user)

    if request.method == "POST":
        form = EditProfileForm(request.POST, request.FILES, instance=request.user, user=request.user)
        if form.is_valid():
            user = form.save()
            # update profile pic if provided
            profile.profile_pic = form.cleaned_data.get("profile_pic") or profile.profile_pic
            profile.save()

            # Redirect depending on role
            if user.is_superuser or getattr(user, "role", None) == "admin":
                return redirect("admin_profile")
            elif getattr(user, "role", None) == "employer":
                return redirect("employer_profile")
            else:
                return redirect("profile")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = EditProfileForm(instance=request.user, user=request.user)

    return render(request, "change_credentials.html", {
        "form": form,
        "profile_picture_url": profile.profile_pic.url if getattr(profile, "profile_pic", None) else None
    })


# -------------------------------------------------------------------
# Job posting / editing / deleting / listing / details
# -------------------------------------------------------------------

@login_required
def post_job(request):
    # only employers
    if not (request.user.is_superuser or getattr(request.user, "role", None) == "employer"):
        return redirect("dashboard")

    if request.method == "POST":
        form = JobForm(request.POST)
        if form.is_valid():
            job = form.save(commit=False)
            job.employer = request.user
            job.save()

            # send alerts to matching JobAlert records (basic matching)
            matches = JobAlert.objects.filter(
                job_title__icontains=job.title,
                location__iexact=job.location
            )

            job_link = request.build_absolute_uri(reverse("apply_job", kwargs={"job_id": job.id}))

            for alert in matches:
                html_content = render_to_string('job_alert_email.html', {
                    "user": alert.user,
                    "job": job,
                    "job_url": job_link
                })
                msg = EmailMultiAlternatives(
                    subject=f"New {job.title} Job Posted!",
                    body=f"A new job matching your alert ({job.title} in {job.location}) is now on JobLink Kenya.",
                    to=[alert.user.email]
                )
                msg.attach_alternative(html_content, "text/html")
                try:
                    msg.send()
                except Exception:
                    # avoid failing whole request if email fails; you may want to log
                    pass

                Notification.objects.create(
                    user=alert.user,
                    title="New Job Alert",
                    message=f"A new job '{job.title}' has been posted in {job.location}.",
                )

            messages.success(request, "Job posted, email alerts & notifications sent.")
            return redirect("dashboard")
        else:
            messages.error(request, "Please correct the errors in the form.")
    else:
        form = JobForm()

    return render(request, "post_job.html", {"form": form})


@login_required
def edit_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, employer=request.user)

    if request.method == "POST":
        form = JobForm(request.POST, instance=job)
        if form.is_valid():
            job = form.save(commit=False)
            job.employer = request.user
            job.save()
            messages.success(request, "Job updated successfully.")
            return redirect("dashboard")
    else:
        form = JobForm(instance=job)

    return render(request, "edit_job.html", {"form": form, "job": job})


@login_required
def view_posted_jobs(request):
    if not request.user.is_superuser and request.user.role != "employer":
        return redirect("login")

    posted_jobs = Job.objects.filter(employer=request.user).order_by("-posted_on")
    posted_jobs_count = posted_jobs.count()
    active_jobs = Job.objects.filter(employer=request.user, is_active=True).count()
    jobs = Job.objects.all().order_by("-posted_on")

    # Allow deletion via POST (with job_id)
    if request.method == "POST":
        job_id = request.POST.get("job_id")
        if job_id:
            job = get_object_or_404(Job, id=job_id, employer=request.user)
            job.delete()
            messages.success(request, f"Job '{job.title}' deleted successfully.")
            return redirect("view_posted_jobs")
        else:
            messages.error(request, "Job ID is missing.")

    return render(request, "view_posted_jobs.html", {
        "jobs": jobs,
        "posted_jobs": posted_jobs,
        "posted_jobs_count": posted_jobs_count,
        "active_jobs": active_jobs
    })


@login_required
def confirm_delete(request, job_id):
    job = get_object_or_404(Job, id=job_id, employer=request.user)
    if request.method == "POST":
        job.delete()
        messages.success(request, "✅ Job deleted successfully!")
        return redirect("view_posted_jobs")
    return render(request, "confirm_delete.html", {"job": job})


# Job listings and detail (public)
def job_list(request):
    premium_jobs = Job.objects.filter(is_premium=True).order_by("-posted_on")
    regular_jobs = Job.objects.filter(is_premium=False).order_by("-posted_on")
    return render(request, "job_list.html", {
        "premium_jobs": premium_jobs,
        "jobs": regular_jobs
    })


@login_required
def job_detail(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    application = None
    if getattr(request.user, "role", None) == "applicant":
        application = Application.objects.filter(job=job, applicant=request.user).first()
    return render(request, "job_detail.html", {"job": job, "application": application})


# -------------------------------------------------------------------
# Apply to job (free & premium flows)
# -------------------------------------------------------------------

@login_required
def apply_job(request, job_id):
    job = get_object_or_404(Job, id=job_id)

    # Prevent employer from applying to own job
    if job.employer == request.user:
        messages.error(request, "❌ You cannot apply to your own job posting.")
        return redirect("job_list")

    # FREE JOB FLOW
    if not job.is_premium:
        if request.method == "POST":
            application, created = Application.objects.get_or_create(applicant=request.user, job=job)
            if created:
                Notification.objects.create(
                    user=job.employer,
                    title="New Job Application",
                    message=f"{request.user.username} has applied for your job '{job.title}'. (job_id={job.id})"
                )
                messages.success(request, "✅ You have successfully applied to the job!")
                applied_status = "yes"
            else:
                applied_status = "already"
                messages.info(request, "ℹ️ You already applied for this job.")
            return redirect("apply_job_success", job_id=job.id, applied=applied_status)
        return render(request, "apply_job.html", {"job": job})

    # PREMIUM JOB FLOW - stripe checkout
    amount = 200 * 100  # KES 200 in cents
    if request.method == "POST":
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[{
                    "price_data": {
                        "currency": "kes",
                        "product_data": {"name": f"Application Fee - {job.title}"},
                        "unit_amount": amount
                    },
                    "quantity": 1
                }],
                mode="payment",
                success_url=request.build_absolute_uri(f"/apply-success/{job.id}/yes/"),
                cancel_url=request.build_absolute_uri(f"/apply-cancel/{job.id}/"),
                metadata={"job_id": job.id, "user_id": request.user.id}
            )
            return redirect(checkout_session.url)
        except stripe.error.StripeError as e:
            return render(request, "apply_job.html", {"job": job, "error": getattr(e, "user_message", str(e))})
        except Exception as e:
            return render(request, "apply_job.html", {"job": job, "error": str(e)})

    return render(request, "apply_job.html", {"job": job})


@login_required
def apply_job_success(request, job_id, applied=True):
    job = get_object_or_404(Job, pk=job_id)
    if str(applied) == "yes":
        application, created = Application.objects.get_or_create(applicant=request.user, job=job)
        if created:
            Notification.objects.create(
                user=job.employer,
                title="New Job Application",
                message=f"{request.user.username} has applied for your job '{job.title}'. (job_id={job.id})"
            )
            messages.success(request, "✅ You have successfully applied to the job!")
        else:
            messages.info(request, "ℹ️ You already applied for this job.")
    return render(request, "apply_job_success.html", {"job": job, "success": applied})


# -------------------------------------------------------------------
# Applicants view (employer side) & applications listing
# -------------------------------------------------------------------

@login_required
def view_applicants(request):
    job_id = request.GET.get("job_id")

    if job_id:
        applicants = Application.objects.filter(job__id=job_id, job__employer=request.user).select_related("job", "applicant")
        applicants_count = applicants.count()
        jobs = Job.objects.filter(id=job_id, employer=request.user)
    else:
        jobs = Job.objects.filter(employer=request.user)
        applicants = Application.objects.filter(job__in=jobs).select_related("job", "applicant")
        applicants_count = applicants.count()

    return render(request, "view_applicants.html", {
        "jobs": jobs,
        "applicants": applicants,
        "applicants_count": applicants_count,
        "job_id": job_id,
    })


@login_required
def view_applications(request):
    if getattr(request.user, "role", None) != "applicant":
        messages.error(request, "❌ Only applicants can access this page.")
        return redirect("dashboard")

    applications = Application.objects.filter(applicant=request.user).select_related("job", "job__employer").order_by("-applied_on")
    return render(request, "view_applications.html", {"applications": applications, "applications_count": applications.count()})


# -------------------------------------------------------------------
# CV Upload / Download
# -------------------------------------------------------------------

@login_required
def upload_cv(request):
    form = CVUploadForm(request.POST or None, request.FILES or None)
    if form.is_valid():
        cv = form.save(commit=False)
        cv.applicant = request.user
        cv.save()
        return redirect("profile")
    return render(request, "upload_CV.html", {"form": form})


@login_required
def download_cv(request, cv_id):
    cv = get_object_or_404(CVUpload, id=cv_id)

    if not getattr(cv, "cv", None):
        return HttpResponse("No CV uploaded.", status=404)

    # fetch file (works if file is hosted on external URL)
    try:
        response = requests.get(cv.cv.url, stream=True, timeout=10)
    except Exception:
        return HttpResponse("Error downloading CV.", status=500)

    if response.status_code != 200:
        return HttpResponse("Error downloading CV.", status=500)

    temp_file = NamedTemporaryFile(delete=True)
    for chunk in response.iter_content(1024):
        temp_file.write(chunk)
    temp_file.flush()

    filename = f"{getattr(cv, 'applicant').username}_CV.pdf" if getattr(cv, "applicant", None) else "CV.pdf"

    return FileResponse(open(temp_file.name, "rb"), as_attachment=True, filename=filename)


# -------------------------------------------------------------------
# Resources, job alerts, admin
# -------------------------------------------------------------------

def resources(request):
    items = SkillResource.objects.all()
    return render(request, "resources.html", {"items": items})


def job_alerts_view(request):
    if not request.user.is_authenticated:
        return redirect("login")
    alerts = JobAlert.objects.filter(user=request.user)
    if request.method == "POST":
        JobAlert.objects.create(
            user=request.user,
            job_title=request.POST.get("job_title", ""),
            location=request.POST.get("location", "")
        )
        return redirect("job_alerts")
    return render(request, "job_alerts.html", {"alerts": alerts})


def delete_alert(request, alert_id):
    try:
        alert = JobAlert.objects.get(id=alert_id, user=request.user)
    except JobAlert.DoesNotExist:
        messages.warning(request, "That job alert does not exist or was already deleted.")
        return redirect("delete_alert_success")

    if request.method == "POST":
        alert.delete()
        messages.success(request, "Job alert deleted successfully.")
        return redirect("delete_alert_success")

    return render(request, "delete_alert.html", {"alert": alert})


def delete_alert_success(request):
    return render(request, "delete_alert_success.html")


# -------------------------------------------------------------------
# Admin-only views
# -------------------------------------------------------------------

@login_required
@user_passes_test(lambda u: u.is_superuser or getattr(u, "role", None) == "admin")
def admin_dashboard(request):
    context = {
        "total_users": User.objects.count(),
        "total_jobs": Job.objects.count(),
        "total_alerts": JobAlert.objects.count(),
        "total_reports": 0,
        "recent_users": User.objects.order_by("-date_joined")[:5],
    }
    return render(request, "admin_dashboard.html", context)


@login_required
def admin_profile(request):
    if not (request.user.is_superuser or getattr(request.user, "role", None) == "admin"):
        return redirect("dashboard")
    return render(request, "admin_profile.html", {"admin": request.user})


@login_required
def admin_only_view(request):
    if getattr(request.user, "role", None) != "admin":
        return redirect("home")
    return render(request, "admin_only.html")


# -------------------------------------------------------------------
# Resume builder / view / download
# -------------------------------------------------------------------

@login_required
def build_resume(request):
    resume, created = Resume.objects.get_or_create(user=request.user)
    if request.method == "POST":
        form = ResumeForm(request.POST, request.FILES, instance=resume)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ Resume saved successfully.")
            return redirect("resume_success")
        else:
            messages.error(request, "❌ Please fix the errors below.")
    else:
        form = ResumeForm(instance=resume)
    return render(request, "resume_builder.html", {"form": form})


@login_required
def edit_resume(request):
    try:
        resume = Resume.objects.get(user=request.user)
    except Resume.DoesNotExist:
        return redirect("build_resume")

    if request.method == "POST":
        form = ResumeForm(request.POST, request.FILES, instance=resume)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ Your resume has been updated successfully.")
            return redirect("view_resume")
        else:
            messages.error(request, "❌ Please fix the errors below.")
    else:
        form = ResumeForm(instance=resume)
    return render(request, "edit_resume.html", {"form": form})


@login_required
def view_resume(request):
    resume = Resume.objects.filter(user=request.user).first()
    return render(request, "view_resume.html", {"resume": resume})


@login_required
def download_resume_pdf(request):
    """
    Generate PDF from HTML resume template with WeasyPrint.
    """
    resume = get_object_or_404(Resume, user=request.user)
    html_string = render_to_string("resume_template.html", {"resume": resume})
    pdf_file = HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf()
    response = HttpResponse(pdf_file, content_type="application/pdf")
    response["Content-Disposition"] = "attachment; filename=resume.pdf"
    return response


def resume_success(request):
    return render(request, "resume_success.html")


# -------------------------------------------------------------------
# Job suggestions (skill matching)
# -------------------------------------------------------------------

@login_required
def job_suggestions(request):
    user = request.user
    skills_str = getattr(user, "skills", "") or ""
    skills = [s.strip().lower() for s in skills_str.split(",") if s.strip()]

    if skills:
        query = Q()
        for skill in skills:
            for word in skill.split():
                query |= Q(title__icontains=word) | Q(description__icontains=word)
        suggested_jobs = Job.objects.filter(query).distinct()
        if not suggested_jobs.exists():
            messages.warning(request, "No jobs matched your skills. Try updating your profile for better matches.")
    else:
        if not request.session.get("skills_message_shown", False):
            messages.info(request, "Add skills in your profile to get better job matches.")
            request.session["skills_message_shown"] = True
        suggested_jobs = Job.objects.none()

    return render(request, "suggestions.html", {"suggested_jobs": suggested_jobs})


# -------------------------------------------------------------------
# Premium job upgrade & payments
# -------------------------------------------------------------------

@login_required
def upgrade_job(request, job_id):
    job = get_object_or_404(Job, pk=job_id, employer=request.user)

    if request.method == "POST":
        form = JobPlanSelectForm(request.POST)
        if form.is_valid():
            plan = form.cleaned_data["plan"]
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[{
                    "price_data": {
                        "currency": "kes",
                        "unit_amount": int(plan.price * 100),
                        "product_data": {"name": f"Premium Upgrade - {plan.name}"},
                    },
                    "quantity": 1,
                }],
                mode="payment",
                success_url=request.build_absolute_uri(f"/payment-success/{job.id}/{plan.id}/"),
                cancel_url=request.build_absolute_uri("/payment-cancelled/"),
            )
            return redirect(checkout_session.url, code=303)
    else:
        form = JobPlanSelectForm()

    return render(request, "upgrade_job.html", {"form": form, "job": job})


@login_required
def payment_success(request, job_id, plan_id):
    job = get_object_or_404(Job, pk=job_id, employer=request.user)
    plan = get_object_or_404(JobPlan, pk=plan_id)

    JobPayment.objects.create(
        employer=request.user,
        job=job,
        plan=plan,
        amount=plan.price,
        is_successful=True
    )

    # mark job as premium and set expiry
    job.is_premium = True
    job.premium_expiry = timezone.now() + timezone.timedelta(days=plan.duration_days)
    job.save()

    messages.success(request, "Job upgraded to premium successfully!")
    return redirect("dashboard")


def payment_cancelled(request):
    messages.error(request, "Payment was cancelled.")
    return redirect("dashboard")


# -------------------------------------------------------------------
# Change username/password
# -------------------------------------------------------------------

@login_required
def change_username_password(request):
    if request.method == "POST":
        form = ChangeUsernamePasswordForm(request.POST, user=request.user, instance=request.user)
        if form.is_valid():
            user = form.save(commit=False)
            # set password properly
            user.set_password(form.cleaned_data["new_password1"])
            user.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Account updated successfully!")
            return redirect("profile")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ChangeUsernamePasswordForm(user=request.user, instance=request.user)

    return render(request, "change_username_password.html", {"form": form})


# -------------------------------------------------------------------
# Chat system - unified chat view + API endpoints
# -------------------------------------------------------------------

@login_required
def chat_view(request, application_id=None, job_id=None):
    """
    Unified chat view handling:
      - application_id present → applicant or direct application chat page
      - job_id present → employer viewing chats for that job (with optional ?app_id=)
      - neither → generic landing depending on user role
    """
    user = request.user
    context = {
        "application": None,
        "job": None,
        "applications": [],
        "selected_app": None,
        "messages": [],
        "jobs": [],
    }

    # Case 1: Applicant chat (direct)
    if application_id:
        app = get_object_or_404(
            Application.objects.select_related("job", "applicant", "job__employer"),
            id=application_id
        )

        # Security check - only applicant or employer can view
        if user.id not in (app.applicant_id, app.job.employer_id):
            return redirect("job_detail", job_id=app.job_id)

        # Post new message
        if request.method == "POST":
            text = request.POST.get("message")
            if text:
                ChatMessage.objects.create(application=app, sender=user, message=text)
                recipient = app.job.employer if user == app.applicant else app.applicant
                Notification.objects.create(
                    user=recipient,
                    title="New Chat Message",
                    message=f"{user.username} sent you a new message about '{app.job.title}'."
                )

        messages_qs = app.messages.all().order_by("timestamp")
        selected_app = app

        # mark as read messages coming from other side
        if user == app.applicant:
            ChatMessage.objects.filter(application=app, sender_id=app.job.employer_id, is_read=False).update(is_read=True)

        context.update({
            "application": app,
            "messages": messages_qs,
            "selected_app": selected_app,
        })
        # If AJAX request, return JSON
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JsonResponse({
                "messages": [
                    {
                        "id": m.id,
                        "sender_id": m.sender_id,
                        "text": m.message,
                        "created": m.timestamp.strftime("%Y-%m-%d %H:%M"),
                    } for m in messages_qs
                ],
                "selected_app_id": selected_app.id if selected_app else None
            })
        return render(request, "chat.html", context)

    # Case 2: Employer chat for a job
    if job_id:
        job = get_object_or_404(Job, id=job_id, employer=user)
        applications = job.applications.select_related("applicant").annotate(
            unread_count=Count(
                "messages",
                filter=Q(messages__is_read=False) & Q(messages__sender_id=F("applicant_id"))
            )
        )

        selected_app = None
        selected_app_id = request.GET.get("app_id")
        if selected_app_id:
            try:
                selected_app_id = int(selected_app_id)
                selected_app = applications.filter(id=selected_app_id).first()
            except (ValueError, TypeError):
                selected_app = None

        if not selected_app:
            selected_app = applications.first() if applications.exists() else None

        if request.method == "POST" and selected_app:
            text = request.POST.get("message")
            if text:
                ChatMessage.objects.create(application=selected_app, sender=user, message=text)
                Notification.objects.create(
                    user=selected_app.applicant,
                    title="New Chat Message",
                    message=f"{user.username} (employer) sent you a new message about '{selected_app.job.title}'."
                )

        messages_qs = selected_app.messages.all().order_by("timestamp") if selected_app else []

        # mark as read messages from applicant when employer views
        if selected_app:
            ChatMessage.objects.filter(
                application=selected_app,
                sender_id=selected_app.applicant_id,
                is_read=False
            ).update(is_read=True)

        context.update({
            "job": job,
            "applications": applications,
            "selected_app": selected_app,
            "messages": messages_qs,
        })

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JsonResponse({
                "messages": [
                    {
                        "id": m.id,
                        "sender_id": m.sender_id,
                        "text": m.message,
                        "created": m.timestamp.strftime("%Y-%m-%d %H:%M"),
                    } for m in messages_qs
                ],
                "selected_app_id": selected_app.id if selected_app else None
            })

        return render(request, "chat.html", context)

    # Case 3: General landing (no ids)
    # If employer, show jobs with applications; if applicant, show their applications
    if getattr(user, "role", None) == "employer":
        jobs = Job.objects.filter(employer=user).prefetch_related("applications__applicant")
        job = None
        applications = []
        selected_app = None
        messages_qs = []

        job_id_param = request.GET.get("job_id")
        if job_id_param:
            try:
                job = jobs.filter(id=int(job_id_param)).first()
            except (ValueError, TypeError):
                job = None

        if not job and jobs.exists():
            job = jobs.first()

        if job:
            applications = job.applications.select_related("applicant").annotate(
                unread_count=Count(
                    "messages",
                    filter=Q(messages__is_read=False) & Q(messages__sender_id=F("applicant_id"))
                )
            )
            selected_app_id = request.GET.get("app_id")
            if selected_app_id:
                try:
                    selected_app = applications.filter(id=int(selected_app_id)).first()
                except (ValueError, TypeError):
                    selected_app = None

            if not selected_app and applications.exists():
                selected_app = applications.first()

            if selected_app:
                messages_qs = selected_app.messages.all().order_by("timestamp")

        context.update({
            "jobs": jobs,
            "job": job,
            "applications": applications,
            "selected_app": selected_app,
            "messages": messages_qs,
        })
        return render(request, "chat.html", context)

    else:
        # applicant landing
        applications = Application.objects.filter(applicant=user).select_related("job__employer").order_by("-applied_on")
        selected_app = None
        messages_qs = []

        selected_app_id = request.GET.get("app_id")
        if selected_app_id:
            try:
                selected_app = applications.filter(id=int(selected_app_id)).first()
            except (ValueError, TypeError):
                selected_app = None

        if not selected_app and applications.exists():
            selected_app = applications.first()

        if selected_app:
            messages_qs = selected_app.messages.all().order_by("timestamp")

        context.update({
            "applications": applications,
            "selected_app": selected_app,
            "messages": messages_qs,
        })
        return render(request, "chat.html", context)


@login_required
def delete_message(request, msg_id):
    msg = get_object_or_404(ChatMessage, id=msg_id, sender=request.user)
    msg.delete()
    return JsonResponse({"status": "ok"})


@login_required
def edit_message(request, msg_id):
    msg = get_object_or_404(ChatMessage, id=msg_id, sender=request.user)
    new_text = request.POST.get("message")
    if new_text:
        msg.message = new_text
        msg.save()
    return JsonResponse({"status": "ok", "new_text": msg.message})


# -------------------------------------------------------------------
# Process application (accept/reject) with email notification
# -------------------------------------------------------------------

@login_required
def process_application(request, app_id):
    application = get_object_or_404(Application, id=app_id)

    # Only employer of the job should be able to change status
    if application.job.employer != request.user:
        messages.error(request, "Unauthorized")
        return redirect("dashboard")

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "accept":
            application.status = "accepted"
            subject = "Job Application Approved ✅"
            message = f"Congratulations! Your application for {application.job.title} has been accepted."
        else:
            application.status = "rejected"
            subject = "Job Application Result ❌"
            message = f"Sorry, your application for {application.job.title} has been rejected."

        application.save()

        # try to send email but do not crash if email backend misconfigured
        try:
            send_mail(subject, message, getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@example.com"),
                      [application.applicant.email])
        except Exception:
            pass

    return redirect("dashboard")


# -------------------------------------------------------------------
# Upgrade: small helper / extra views
# -------------------------------------------------------------------

@login_required
def employer_control_panel_view(request):
    if not request.user.is_superuser and getattr(request.user, "role", None) != "employer":
        return redirect("login")

    posted_jobs_count = Job.objects.filter(employer=request.user).count()
    active_jobs = Job.objects.filter(employer=request.user, is_active=True).count()
    applicants_count = Application.objects.filter(job__employer=request.user).count()

    return render(request, "employer_dashboard.html", {
        "posted_jobs_count": posted_jobs_count,
        "active_jobs": active_jobs,
        "applicants_count": applicants_count,
    })

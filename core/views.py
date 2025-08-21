from django.shortcuts import render, redirect, get_object_or_404 
from django.contrib.auth import login, logout, authenticate 
from django.contrib import messages 
from django.contrib.auth.decorators import login_required, user_passes_test 
from django.contrib.auth.models import User 
from django.http import HttpResponse 
from django.template.loader import get_template, render_to_string 
from django.core.mail import EmailMultiAlternatives 
from django.utils import timezone 
from django.db.models import Q
from .forms import EditProfileForm, UserForm, ProfileForm, RegisterForm, JobForm, ResumeForm, CVUploadForm, JobPlanSelectForm, CustomUserCreationForm, ChangeUsernamePasswordForm 
from .models import JobAlert, ChatMessage, Application, Job, SkillResource, Resume, CVUpload, JobPlan, JobPayment, Profile 
import pdfkit
from django.contrib.auth import update_session_auth_hash
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
import stripe
from django.conf import settings
from weasyprint import HTML
from django.http import FileResponse, Http404
import os
from django.http import HttpResponseRedirect, FileResponse
import requests
from django.core.files.temp import NamedTemporaryFile
from django.http import JsonResponse


@login_required
def process_application(request, app_id):
    """
    Employer accepts or rejects a job application
    & email is sent automatically to the applicant.
    """
    application = get_object_or_404(Application, id=app_id)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'accept':
            application.status = 'accepted'
            subject = 'Job Application Approved ✅'
            message = f'Congratulations! Your application for {application.job.title} has been accepted.'

        else:  # reject
            application.status = 'rejected'
            subject = 'Job Application Result ❌'
            message = f'Sorry, your application for {application.job.title} has been rejected.'

        application.save()

        # send email to applicant
        send_mail(
            subject,
            message,
            'linux7506@gmail.com',      # from email
            [application.applicant.email],     # user's email
        )

    return redirect('dashboard')  # <— change to your employer dashboard URL name
    
User = get_user_model()

#Home Page

def home(request):
    return render(request, 'home.html')

#User Signup

def signup_view(request):
     if request.method == 'POST':
         form = CustomUserCreationForm(request.POST)
         if form.is_valid():
             user = form.save()
             login(request, user)
             return redirect('login')
     else:
         form = CustomUserCreationForm() 
     return render(request, 'signup.html', {'form': form})

#User Login

def login_view(request): 
    if request.method == 'POST': 
        username = request.POST['username'] 
        password = request.POST['password'] 
        user = authenticate(request, username=username, password=password) 
        if user is not None:
            login(request, user)

            # SUPERUSER GOES DIRECTLY TO ADMIN DASHBOARD
            if user.is_superuser:
                return redirect('admin_dashboard')

            # Normal users go to dashboard
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials")
    return render(request, 'login.html')

#User Logout

def logout_view(request):
    logout(request)
    return redirect('logout_success')

# Logout success message
def logout_success(request):
    return render(request, 'logout_success.html')

#Dashboard

def dashboard(request):
    user = request.user

    if not user.is_authenticated:
        return redirect('login')

    # If admin, redirect them to the admin dashboard instead of applicant/employer
    if user.is_superuser or user.role == 'admin':
        return redirect('admin_dashboard')

    # Normal logic for employer/applicant
    if hasattr(user, 'role'):
        if user.role == 'applicant':
            return render(request, 'applicant_dashboard.html')

        elif user.role == 'employer':
            posted_jobs_count = Job.objects.filter(employer=user).count()
            active_jobs = Job.objects.filter(employer=user, is_active=True).count()
            applicants_count = Application.objects.filter(job__employer=user).count()

            return render(request, 'employer_dashboard.html', {
                'posted_jobs_count': posted_jobs_count,
                'active_jobs': active_jobs,
                'applicants_count': applicants_count
            })

    # Fallback
    return redirect('login')

@login_required
def profile_view(request):
    user = request.user  # CustomUser instance

    # Latest CV
    try:
        user_cv = CVUpload.objects.filter(applicant=user).latest('id')
    except CVUpload.DoesNotExist:
        user_cv = None

    # Convert skills string from CustomUser to a list (comma-separated)
    skills_list = []
    if user.skills:
        skills_list = [skill.strip() for skill in user.skills.split(',')]

    context = {
        'user': user,
        'user_cv': user_cv,
        'skills': skills_list,  # Pass skills list directly
        'profile_picture_url': user.profile_pic.url if user.profile_pic else None,
    }

    template_name = 'employer_profile.html' if user.role == 'employer' else 'profile.html'
    return render(request, template_name, context)

@login_required
def view_posted_jobs(request):
    if not request.user.is_superuser and request.user.role != 'employer':
        return redirect('login')
    jobs = Job.objects.all().order_by('-posted_on')
    posted_jobs = Job.objects.filter(employer=request.user).order_by('-posted_on')
    posted_jobs_count = posted_jobs.count()
    active_jobs = Job.objects.filter(employer=request.user, is_active=True).count()
    if request.method == 'POST':
        job_id = request.POST.get('job_id')
        if job_id:
            job = get_object_or_404(Job, id=job_id, employer=request.user)
            job.delete()
            messages.success(request, f"Job '{job.title}' deleted successfully.")
            return redirect('view_posted_jobs')
        else:
            messages.error(request, f"Job ID is missing.")
    return render(request, 'view_posted_jobs.html', {
        'jobs': jobs,
        'posted_jobs': posted_jobs,
        'posted_jobs_count': posted_jobs_count,
        'active_jobs': active_jobs
    })

@login_required
def view_applicants(request):
    jobs = Job.objects.filter(employer=request.user)
    applicants = Application.objects.filter(job__in=jobs).select_related('job', 'applicant')
    applicants_count = applicants.count()
    return render(request, 'view_applicants.html', {
        'applicants': applicants,
        'applicants_count': applicants_count
    })

@login_required
def employer_control_panel_view(request):
    if not request.user.is_superuser and request.user.role != 'employer':
        return redirect('login')

    posted_jobs_count = Job.objects.filter(employer=request.user).count()
    active_jobs = Job.objects.filter(employer=request.user, is_active=True).count()
    applicants_count = Application.objects.filter(job__employer=request.user).count()

    return render(request, 'employer_dashboard.html', {
        'posted_jobs_count': posted_jobs_count,
        'active_jobs': active_jobs,
        'applicants_count': applicants_count,
    })
  
@login_required
def employer_profile(request):
    return render(request, 'employer_profile.html', {
        'user': request.user
    })

@login_required
def admin_profile(request):
    """
    Simple admin profile page that shows details of the logged-in superuser.
    """
    if not (request.user.is_superuser or request.user.role == 'admin'):
        return redirect('dashboard')   # block access for normal users

    return render(request, 'admin_profile.html', {
        'admin': request.user,
    })

def edit_profile(request):
    profile, created = Profile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = EditProfileForm(request.POST, request.FILES, instance=request.user, user=request.user)

        if form.is_valid():
            user = form.save()
            profile.profile_pic = form.cleaned_data.get('profile_pic') or profile.profile_pic
            profile.save()

            # Redirect to correct profile automatically
            if user.is_superuser or user.role == 'admin':
                return redirect('admin_profile')
            elif user.role == 'employer':
                return redirect('employer_profile')
            else:
                return redirect('profile')
    else:
        form = EditProfileForm(instance=request.user, user=request.user)

    return render(request, 'change_credentials.html', {
        'form': form,
        'profile_picture_url': profile.profile_pic.url if profile.profile_pic else None
    })

#Job Posting

@login_required
def post_job(request):
    if request.method == 'POST':
        form = JobForm(request.POST)
        if form.is_valid():
            job = form.save(commit=False)
            job.employer = request.user
            job.save()

            # ---- send email notifications to matching alerts ----
            matches = JobAlert.objects.filter(
                job_title__icontains=job.title,
                location__iexact=job.location
            )

            job_link = request.build_absolute_uri(
                reverse('apply_job', kwargs={'job_id': job.id})
            )

            for alert in matches:
                html_content = render_to_string('job_alert_email.html', {
                    'user': alert.user,
                    'job': job,
                    'job_url': job_link
                })
                msg = EmailMultiAlternatives(
                    subject=f"New {job.title} Job Posted!",
                    body=f"A new job matching your alert ({job.title} in {job.location}) is now on JobLink Kenya.",
                    to=[alert.user.email]
                )
                msg.attach_alternative(html_content, "text/html")
                msg.send()
            # -----------------------------------------------------

            messages.success(request, "Job posted and email alerts sent to applicants.")
            return redirect('dashboard')
    else:
        form = JobForm()
    return render(request, 'post_job.html', {'form': form})

@login_required
def edit_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, employer=request.user)  # only employer can edit

    if request.method == 'POST':
        form = JobForm(request.POST, instance=job)
        if form.is_valid():
            job = form.save(commit=False)
            job.employer = request.user  # just to be safe
            job.save()

            messages.success(request, "Job updated successfully.")
            return redirect('dashboard')  # or job_detail page
    else:
        form = JobForm(instance=job)

    return render(request, 'edit_job.html', {'form': form, 'job': job})


#Apply Job
@login_required
def apply_job(request, job_id):
    job = get_object_or_404(Job, id=job_id)

    # Prevent employer from applying to their own job
    if job.employer == request.user:
        messages.error(request, "❌ You cannot apply to your own job posting.")
        return redirect('job_list')

    # ---------- FREE JOB FLOW ----------
    if not job.is_premium:
        if request.method == "POST":
            application, created = Application.objects.get_or_create(
                applicant=request.user,
                job=job
            )
            applied_status = 'yes' if created else 'already'
            messages.success(request, "✅ You have successfully applied to the job!")
            return redirect('apply_job_success', job_id=job.id, applied=applied_status)

        # GET request → Show application page
        return render(request, 'apply_job.html', {'job': job})

    # ---------- PREMIUM JOB FLOW ----------
    amount = 200 * 100  # KES 200 in cents

    if request.method == "POST":
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'kes',
                        'product_data': {
                            'name': f"Application Fee - {job.title}",
                        },
                        'unit_amount': amount,
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=request.build_absolute_uri(f'/apply-success/{job.id}/yes/'),
                cancel_url=request.build_absolute_uri(f'/apply-cancel/{job.id}/'),
                metadata={
                    'job_id': job.id,
                    'user_id': request.user.id
                }
            )
            return redirect(checkout_session.url)

        except stripe.error.StripeError as e:
            return render(request, 'apply_job.html', {'job': job, 'error': str(e.user_message)})
        except Exception as e:
            return render(request, 'apply_job.html', {'job': job, 'error': str(e)})

    # GET request for premium job → Show application page
    return render(request, 'apply_job.html', {'job': job})


@login_required
def apply_job_success(request, job_id, applied=True):
    job = get_object_or_404(Job, pk=job_id)
    return render(request, 'apply_job_success.html', {
        'job': job,
        'success': applied
    })

#CV Upload

@login_required
def upload_cv(request):
    form = CVUploadForm(request.POST or None, request.FILES or None)
    if form.is_valid():
        cv = form.save(commit=False)
        cv.applicant = request.user
        cv.save()
        return redirect('profile')
    return render(request, 'upload_CV.html', {'form': form})

@login_required
def download_cv(request, cv_id):
    cv = get_object_or_404(CVUpload, id=cv_id)

    if not cv.cv:
        return HttpResponse("No CV uploaded.", status=404)

    # Download file from Cloudinary
    response = requests.get(cv.cv.url, stream=True)
    if response.status_code != 200:
        return HttpResponse("Error downloading CV.", status=500)

    # Save to temporary file
    temp_file = NamedTemporaryFile(delete=True)
    for chunk in response.iter_content(1024):
        temp_file.write(chunk)
    temp_file.flush()

    # Use the correct applicant field for filename
    applicant_name = getattr(cv, 'applicant', None)
    if applicant_name:
        filename = f"{cv.applicant.username}_CV.pdf"
    else:
        filename = "CV.pdf"

    # Serve file as attachment
    return FileResponse(
        open(temp_file.name, 'rb'),
        as_attachment=True,
        filename=filename
    )
#Job Listings

def job_list(request):
    premium_jobs = Job.objects.filter(is_premium=True).order_by('-posted_on')
    regular_jobs = Job.objects.filter(is_premium=False).order_by('-posted_on')
    return render(request, 'job_list.html', {
        'premium_jobs': premium_jobs,
        'jobs': regular_jobs
    })


def job_detail(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    return render(request, "job_detail.html", {"job": job})

#Learning Resources

def resources(request):
    items = SkillResource.objects.all()
    return render(request, 'resources.html', {'items': items})

#Job Alerts

def job_alerts_view(request):
    alerts = JobAlert.objects.filter(user=request.user)
    if request.method == 'POST':
        JobAlert.objects.create(
            user=request.user,
            job_title=request.POST['job_title'],
            location=request.POST['location']
        )
        return redirect('job_alerts')
    return render(request, 'job_alerts.html', {'alerts': alerts})


def delete_alert(request, alert_id):
    try:
        alert = JobAlert.objects.get(id=alert_id, user=request.user)
    except JobAlert.DoesNotExist:
        messages.warning(request, "That job alert does not exist or was already deleted.")
        return redirect('delete_alert_success')

    if request.method == 'POST':
        alert.delete()
        messages.success(request, "Job alert deleted successfully.")
        return redirect('delete_alert_success')

    return render(request, 'delete_alert.html', {'alert': alert})


def delete_alert_success(request):
    return render(request, 'delete_alert_success.html')


@login_required
def confirm_delete(request, job_id):
    job = get_object_or_404(Job, id=job_id, employer=request.user)  # Ensure user owns the job

    if request.method == "POST":
        job.delete()
        messages.success(request, "✅ Job deleted successfully!")
        return redirect('view_posted_jobs')  # Redirect to list after deletion

    return render(request, 'confirm_delete.html', {'job': job})
    
#Admin Dashboard

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role == 'admin')
def admin_dashboard(request):
    context = {
        'total_users': User.objects.count(),
        'total_jobs': Job.objects.count(),
        'total_alerts': JobAlert.objects.count(),
        'total_reports': 0,  # or change to real Report count
        'recent_users': User.objects.order_by('-date_joined')[:5],
    }
    return render(request, 'admin_dashboard.html', context)

@login_required 
def admin_required(user):
    return user.role == 'admin'

@login_required 
def admin_only_view(request):
    if request.user.role != 'admin':
        return redirect('home')
    return render(request, 'admin_only.html')
    
#Resume Builder / download / suggestions
@login_required
def resume_success(request):
    return render(request, 'resume_success.html')

@login_required
def build_resume(request):
    """Create a new resume or update the existing one."""
    resume, created = Resume.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = ResumeForm(request.POST, request.FILES, instance=resume)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ Resume saved successfully.")
            return redirect('resume_success')  # Go straight to view
        else:
            messages.error(request, "❌ Please fix the errors below.")
    else:
        form = ResumeForm(instance=resume)

    return render(request, 'resume_builder.html', {'form': form})


@login_required
def edit_resume(request):
    """Edit an existing resume."""
    resume = get_object_or_404(Resume, user=request.user)

    if request.method == 'POST':
        form = ResumeForm(request.POST, request.FILES, instance=resume)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ Your resume has been updated successfully.")
            return redirect('view_resume')
        else:
            messages.error(request, "❌ Please fix the errors below.")
    else:
        form = ResumeForm(instance=resume)

    return render(request, 'edit_resume.html', {'form': form})


@login_required
def view_resume(request):
    """Display the logged-in user's resume or show a friendly message if none exists."""
    try:
        resume = Resume.objects.get(user=request.user)
    except Resume.DoesNotExist:
        resume = None  # User hasn't created a resume yet

    context = {
        'resume': resume
    }

    return render(request, 'view_resume.html', context)


@login_required
def download_resume_pdf(request):
    """Generate and download resume as PDF without wkhtmltopdf."""
    resume = get_object_or_404(Resume, user=request.user)
    html_string = render_to_string('resume_template.html', {'resume': resume})

    # Generate PDF from HTML string
    pdf_file = HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf()

    # Send PDF as a downloadable file
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="resume.pdf"'
    return response


@login_required
def job_suggestions(request):
    user = request.user
    
    # Ensure skills is always a string before splitting
    skills_str = getattr(user, "skills", "") or ""
    skills = [s.strip().lower() for s in skills_str.split(",") if s.strip()]

    if skills:
        query = Q()
        for skill in skills:
            # Split multi-word skills into words
            for word in skill.split():
                # Partial + case-insensitive match
                query |= Q(title__icontains=word) | Q(description__icontains=word)

        suggested_jobs = Job.objects.filter(query).distinct()

        if not suggested_jobs.exists():
            messages.warning(
                request,
                "No jobs matched your skills. Try updating your profile for better matches."
            )
    else:
        if not request.session.get("skills_message_shown", False):
            messages.info(request, "Add skills in your profile to get better job matches.")
            request.session["skills_message_shown"] = True

        suggested_jobs = Job.objects.none()

    return render(request, "suggestions.html", {
        "suggested_jobs": suggested_jobs
    })
    
#Premium Job Upgrade

stripe.api_key = settings.STRIPE_SECRET_KEY

@login_required
def upgrade_job(request, job_id):
    job = get_object_or_404(Job, pk=job_id, employer=request.user)

    if request.method == 'POST':
        form = JobPlanSelectForm(request.POST)
        if form.is_valid():
            plan = form.cleaned_data['plan']

            # Create Stripe Checkout Session
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'kes',  # Or 'usd' depending on your Stripe setup
                        'unit_amount': int(plan.price * 100),  # Stripe uses cents
                        'product_data': {
                            'name': f"Premium Upgrade - {plan.name}",
                        },
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=request.build_absolute_uri(f'/payment-success/{job.id}/{plan.id}/'),
                cancel_url=request.build_absolute_uri('/payment-cancelled/'),
            )

            return redirect(checkout_session.url, code=303)

    else:
        form = JobPlanSelectForm()

    return render(request, 'upgrade_job.html', {'form': form, 'job': job})

@login_required
def payment_success(request, job_id, plan_id):
    job = get_object_or_404(Job, pk=job_id, employer=request.user)
    plan = get_object_or_404(JobPlan, pk=plan_id)

    # Save payment record
    JobPayment.objects.create(
        employer=request.user,
        job=job,
        plan=plan,
        amount=plan.price,
        is_successful=True
    )

    # Mark job as premium
    job.premium = True
    job.premium_expiry = timezone.now() + timezone.timedelta(days=plan.duration_days)
    job.save()

    messages.success(request, "Job upgraded to premium successfully!")
    return redirect('dashboard')

def payment_cancelled(request):
    messages.error(request, "Payment was cancelled.")
    return redirect('dashboard')
    
@login_required
def change_username_password(request):
    # Instantiate correctly both GET and POST
    if request.method == 'POST':
        form = ChangeUsernamePasswordForm(request.POST, user=request.user, instance=request.user)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['new_password1'])
            user.save()
            update_session_auth_hash(request, user)  # keeps user logged in
            messages.success(request, "Account updated successfully!")
            return redirect('profile')   # make sure this URL name exists
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ChangeUsernamePasswordForm(user=request.user, instance=request.user)

    return render(request, 'change_username_password.html', {'form': form})


@login_required
def chat_view(request, application_id=None, job_id=None):
    """
    Unified chat view for both applicants and employers.
    - Applicants access via application_id
    - Employers access via job_id (with optional ?app_id= query param)
    """
    user = request.user
    context = {
        "application": None,
        "job": None,
        "applications": [],
        "selected_app": None,
        "messages": [],
    }

    messages = []
    selected_app = None

    # Case 1: Applicant chat
    if application_id:
        app = get_object_or_404(
            Application.objects.select_related("job", "applicant", "job__employer"),
            id=application_id
        )

        if user.id not in (app.applicant_id, app.job.employer_id):
            return redirect("job_detail", job_id=app.job_id)

        if request.method == "POST":
            content = request.POST.get("message")
            if content:
                ChatMessage.objects.create(application=app, sender=user, content=content)

        messages = app.messages.all()
        context["messages"] = messages
        context["application"] = app

        selected_app = app

        if user == app.applicant:
            ChatMessage.objects.filter(
                application=app,
                sender_id=app.job.employer_id,
                is_read=False
            ).update(is_read=True)

    # Case 2: Employer chat
    elif job_id:
        job = get_object_or_404(Job, id=job_id, employer=user)
        applications = job.applications.select_related("applicant").all()

        selected_app_id = request.GET.get("app_id")
        if selected_app_id:
            try:
                selected_app_id = int(selected_app_id)
                selected_app = get_object_or_404(Application, id=selected_app_id, job=job)
            except (ValueError, Application.DoesNotExist):
                selected_app = None
        if not selected_app:
            selected_app = applications.first() if applications else None

        if request.method == "POST" and selected_app:
            content = request.POST.get("message")
            if content:
                ChatMessage.objects.create(application=selected_app, sender=user, content=content)

        messages = selected_app.messages.all() if selected_app else []
        context["job"] = job
        context["applications"] = applications
        context["selected_app"] = selected_app
        context["messages"] = messages

        if selected_app:
            ChatMessage.objects.filter(
                application=selected_app,
                sender_id=selected_app.applicant_id,
                is_read=False
            ).update(is_read=True)

    else:
        return redirect("dashboard")

    # ✅ Return JSON if AJAX request
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return JsonResponse({
            "messages": [
                {
                    "id": msg.id,
                    "sender_id": msg.sender_id,
                    "text": msg.content,
                    "created": msg.created_at.strftime("%Y-%m-%d %H:%M"),
                }
                for msg in messages
            ],
            "selected_app_id": selected_app.id if selected_app else None
        })

    # Otherwise render template
    return render(request, "chat.html", context)


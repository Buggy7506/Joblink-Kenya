from django.shortcuts import render, redirect, get_object_or_404 
from core.utils import send_verification_email_smtp
from django.core.mail import send_mail, get_connection
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
from .models import Notification
from django.shortcuts import redirect, render
from django.conf import settings
import requests
import urllib.parse
from datetime import timedelta
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import login, get_user_model
from django.utils import timezone
from django.db.models import Q
from .models import TrustedDevice, DeviceVerification, CustomUser
from .utils import get_client_ip, get_device_name, generate_code
from django.core.mail import send_mail
from django.core.files.base import ContentFile
import re
from collections import namedtuple
from django.db.models import Q

User = get_user_model()


def verify_device(request):
    """
    Verify a new device using a 6-digit code sent via email or SMS.
    Marks device as trusted and logs in the user on successful verification.
    """

    # ----------------------------------------
    # 1️⃣ Make sure session has a pending user
    # ----------------------------------------
    pending_user_id = request.session.get("pending_user_id")
    if not pending_user_id:
        messages.error(request, "No pending verification found. Please login first.")
        return redirect("login")

    try:
        user = CustomUser.objects.get(id=pending_user_id)
    except CustomUser.DoesNotExist:
        messages.error(request, "User not found. Please login again.")
        request.session.flush()
        return redirect("login")

    # ----------------------------------------
    # 2️⃣ POST → check input & validate code
    # ----------------------------------------
    if request.method == "POST":
        code = request.POST.get("code", "").strip()

        if not code:
            messages.error(request, "Please enter the verification code.")
            return render(request, "verify_device.html", {
                "user": user,
                "pending_verification": True
            })

        # Look for valid unused code
        verification = DeviceVerification.objects.filter(
            user=user,
            code=code,
            is_used=False
        ).order_by("-created_at").first()

        if not verification:
            messages.error(request, "Invalid or incorrect verification code.")
            return render(request, "verify_device.html", {
                "user": user,
                "pending_verification": True
            })

        # Check expiry (10 min)
        expiry_time = verification.created_at + timezone.timedelta(minutes=10)
        if timezone.now() > expiry_time:
            verification.is_used = True
            verification.save()

            messages.error(request, "That code has expired. Please request a new one.")
            request.session.flush()
            return redirect("login")

        # Mark code as used
        verification.is_used = True
        verification.save()

        # ----------------------------------------
        # 3️⃣ Save device as trusted
        # ----------------------------------------
        TrustedDevice.objects.create(
            user=user,
            device_name=request.session.get("pending_name"),
            user_agent=request.session.get("pending_ua"),
            ip_address=request.session.get("pending_ip")
        )

        # ----------------------------------------
        # 4️⃣ Log user in
        # ----------------------------------------
        login(request, user)

        # Cleanup
        for key in ["pending_user_id", "pending_ip", "pending_ua",
                    "pending_name", "pending_method"]:
            request.session.pop(key, None)

        messages.success(request, "Device verified and logged in successfully!")
        return redirect("dashboard")

    # ----------------------------------------
    # 5️⃣ GET → show verification page
    # ----------------------------------------
    return render(request, "verify_device.html", {
        "user": user,
        "pending_verification": True
    })


def choose_verification_method(request):
    """
    Let the user choose how to receive the device verification code (email or phone)
    before verifying a new device.
    """

    # 1️⃣ Ensure pending login exists
    pending_user_id = request.session.get("pending_user_id")
    if not pending_user_id:
        messages.error(request, "Please login first.")
        return redirect("login")

    # 2️⃣ Get user object
    try:
        user = CustomUser.objects.get(id=pending_user_id)
    except CustomUser.DoesNotExist:
        messages.error(request, "User not found. Please login again.")
        request.session.flush()
        return redirect("login")

    # 3️⃣ Handle POST → generate & send verification code
    if request.method == "POST":
        method = request.POST.get("method")

        if method not in ["email", "phone"]:
            messages.error(request, "Please select a valid verification method.")
            return redirect("choose_verification_method")

        if method == "phone" and not user.phone:
            messages.error(request, "No phone number on file for this account.")
            return redirect("choose_verification_method")

        if method == "email" and not user.email:
            messages.error(request, "No email on file for this account.")
            return redirect("choose_verification_method")

        # Generate verification code
        code = generate_code()
        DeviceVerification.objects.create(
            user=user,
            code=code,
            device_name=request.session.get("pending_name"),
            user_agent=request.session.get("pending_ua"),
            ip_address=request.session.get("pending_ip")
        )

        # Send SMS OR SMTP EMAIL
        if method == "phone":
            print(f"SMS to {user.phone}: Your verification code is {code}")
        else:
            send_verification_email_smtp(user.email, code)

        # Save method and redirect
        request.session["pending_method"] = method
        return redirect("verify_device")

    # 4️⃣ GET → render
    return render(request, "choose_verification_method.html", {
        "user": user,
        "has_phone": bool(user.phone),
        "pending_verification": True
    })




def set_google_password(request):
    """
    Google OAuth users set a password here.
    User account is created only after a valid password is set.
    """
    google_user = request.session.get('google_user')
    if not google_user:
        messages.error(request, "Session expired. Please login with Google again.")
        return redirect('signup')

    if request.method == 'POST':
        password = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        # -------------------------
        # 1️⃣ Validate inputs
        # -------------------------
        if not password or not confirm_password:
            messages.error(request, "Please fill in both password fields.")
            return render(request, 'set_google_password.html')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'set_google_password.html')

        if len(password) < 6:
            messages.error(request, "Password must be at least 6 characters long.")
            return render(request, 'set_google_password.html')

        # Strength checks
        if not re.search(r'[A-Z]', password):
            messages.error(request, "Password must contain at least one uppercase letter.")
            return render(request, 'set_google_password.html')
        if not re.search(r'\d', password):
            messages.error(request, "Password must contain at least one number.")
            return render(request, 'set_google_password.html')
        if not re.search(r'[@$!%*#?&]', password):
            messages.error(request, "Password must contain at least one special character (@$!%*#?&).")
            return render(request, 'set_google_password.html')

        # -------------------------
        # 2️⃣ Create user account
        # -------------------------
        email = google_user['email']
        first_name = google_user.get('first_name', '')
        last_name = google_user.get('last_name', '')
        role = request.session.get('google_role') or google_user.get('role')  # Role stored in session from role selection

        # Generate unique username
        base_username = ''.join(e for e in first_name.lower() if e.isalnum()) or 'user'
        username = base_username
        counter = 1
        while CustomUser.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        user = CustomUser.objects.create(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            role=role
        )
        user.set_password(password)
        user.save()

        # -------------------------
        # 3️⃣ Save profile picture if available
        # -------------------------
        profile_picture_url = google_user.get('picture')
        if profile_picture_url:
            try:
                response = requests.get(profile_picture_url)
                if response.status_code == 200:
                    user.profile_pic.save(
                        f"{username}_google.jpg",
                        ContentFile(response.content),
                        save=True
                    )
            except Exception as e:
                print("Failed to fetch Google profile picture:", e)

        # -------------------------
        # 4️⃣ Log user in and cleanup
        # -------------------------
        login(request, user)
        request.session.pop('google_user', None)
        if 'google_role' in request.session:
            request.session.pop('google_role')

        messages.success(request, "Account created and logged in successfully!")
        return redirect('dashboard')

    # GET request → show password set page
    return render(request, 'set_google_password.html')

# Google OAuth settings
GOOGLE_CLIENT_ID = '268485346186-pocroj4v0e6dhdufub2m4vaji0ts3ohj.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_REDIRECT_URI = 'https://joblink-kenya-6vrl.onrender.com/google/callback/'
GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_ENDPOINT = 'https://www.googleapis.com/oauth2/v1/userinfo'


def google_login(request):
    """Step 1: Redirect user to Google's OAuth 2.0 server"""
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'consent',
    }
    url = f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    return redirect(url)


def google_callback(request):
    """
    Handle Google OAuth callback.
    - Existing users: log in directly.
    - New users: store info in session and redirect to choose role.
    """
    code = request.GET.get('code')
    if not code:
        return redirect('signup')  # cannot proceed without code

    # Exchange code for access token
    data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    token_response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=data)
    token_data = token_response.json()
    access_token = token_data.get('access_token')

    if not access_token:
        return redirect('signup')  # cannot proceed without access token

    # Get user info from Google
    headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.get(GOOGLE_USERINFO_ENDPOINT, headers=headers)
    user_info = user_response.json()

    email = user_info.get('email')
    first_name = user_info.get('given_name', '')
    last_name = user_info.get('family_name', '')

    # Fallback: parse names from email if missing
    if not first_name or not last_name:
        local_part = email.split('@')[0]  # john.doe@gmail.com -> john.doe
        parts = local_part.split('.')
        first_name = first_name or parts[0].capitalize()
        last_name = last_name or (parts[1].capitalize() if len(parts) > 1 else '')

    if not email:
        return redirect('signup')  # cannot proceed without email

    # Check if user already exists
    try:
        user = User.objects.get(email=email)
        # Existing user: log in directly
        login(request, user)
        return redirect('dashboard')
    except User.DoesNotExist:
        # New user: save info in session and redirect to role selection
        request.session['google_user'] = {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
        }
        return redirect('google_choose_role')

from .models import CustomUser  # Make sure to use your CustomUser

def google_choose_role(request):
    """
    Let user select role after Google OAuth.
    Only first-time users see this page.
    Role selection is stored in session for later account creation.
    Profile picture will be handled later in set_google_password.
    """
    user_data = request.session.get('google_user')
    if not user_data:
        messages.error(request, "Google login required first.")
        return redirect('signup')

    email = user_data['email']

    # If user already exists and has a usable password, log in directly
    try:
        existing_user = CustomUser.objects.get(email=email)
        if existing_user.has_usable_password():
            login(request, existing_user)
            request.session.pop('google_user', None)
            return redirect('dashboard')
    except CustomUser.DoesNotExist:
        pass

    if request.method == 'POST':
        role = request.POST.get('role')
        if role not in ['applicant', 'employer']:
            messages.error(request, "Please select a valid role.")
            return redirect('google_choose_role')

        # Store role in session for later account creation
        request.session['google_role'] = role

        return redirect('set_google_password')

    # GET request → render role selection template
    return render(request, 'google_role.html', {
        "google_user": user_data,
    })


    
# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
def get_unread_messages(user):
    """
    Returns the count of unread chat messages for the given user.
    """
    return ChatMessage.objects.filter(
        is_read=False
    ).filter(
        Q(application__applicant=user) & ~Q(sender=user) |
        Q(application__job__employer=user) & ~Q(sender=user)
    ).count()


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


NotificationItem = namedtuple("NotificationItem", ["title", "message", "timestamp", "is_read", "url"])


@login_required
def notifications(request):
    user = request.user

    notifications = []

    # ---------------------------
    # Unread standard notifications
    # ---------------------------
    base_notifications = Notification.objects.filter(
        user=user, is_read=False
    ).order_by("-timestamp")

    for n in base_notifications:
        url = None

        # Detect job application notifications with job_id embedded in message
        match = re.search(r"job_id=(\d+)", n.message)
        if match:
            job_id = match.group(1)
            url = reverse("view_applicants") + f"?job_id={job_id}"

        notifications.append(
            NotificationItem(
                title=n.title,
                message=n.message.split("(job_id=")[0],  # strip hidden job_id part
                timestamp=n.timestamp,
                is_read=n.is_read,
                url=url,
            )
        )

    # ---------------------------
    # Unread chat messages
    # ---------------------------
    unread_chats = ChatMessage.objects.filter(
        is_read=False
    ).filter(
        Q(application__applicant=user) & ~Q(sender=user) |
        Q(application__job__employer=user) & ~Q(sender=user)
    ).order_by("-timestamp")

    for chat in unread_chats:
        if chat.application.applicant == user:
            chat_url = reverse("job_chat", args=[chat.application.id])
        else:
            chat_url = reverse("employer_chat", args=[chat.application.job.id]) + f"?app_id={chat.application.id}"

        notifications.append(
            NotificationItem(
                title=f"New message from {chat.sender.username}",
                message=chat.message,
                timestamp=chat.timestamp,
                is_read=False,
                url=chat_url,
            )
        )

    # ---------------------------
    # Sort by newest first
    # ---------------------------
    notifications.sort(key=lambda n: n.timestamp, reverse=True)

    total_unread = len(notifications)

    if not notifications:
        messages.info(request, "🔔 You don’t have any notifications yet.")

    context = {
        "notifications": notifications,
        "unread_count": total_unread,
        "role": getattr(user, "role", None),
        "title": "My Notifications",
    }
    return render(request, "notifications.html", context)


@login_required
def mark_all_read(request):
    """
    Marks all unread notifications and unread chat messages for the logged-in user as read.
    """
    user = request.user

    # Mark standard notifications as read
    Notification.objects.filter(user=user, is_read=False).update(is_read=True)

    # Mark unread chat messages as read
    ChatMessage.objects.filter(
        is_read=False
    ).filter(
        Q(application__applicant=user) & ~Q(sender=user) |
        Q(application__job__employer=user) & ~Q(sender=user)
    ).update(is_read=True)

    return redirect("notifications")  # back to notifications page
    
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
             return redirect('dashboard')
     else:
         form = CustomUserCreationForm() 
     return render(request, 'signup.html', {'form': form})

#User Login
from django.contrib.auth import get_user_model

User = get_user_model()


from django.contrib.auth import logout

def login_view(request):
    """
    Handle user login with device verification for untrusted devices.
    Steps:
    1. Identify user by username, email, or phone.
    2. Check if password is set.
    3. Authenticate user.
    4. Check if device is trusted.
    5. If new device, redirect to choose verification method (email/phone).
    """

    # 🔥 Ensure no previous session keeps the user authenticated
    if request.user.is_authenticated:
        logout(request)

    if request.method == 'POST':
        identifier = request.POST.get('identifier', '').strip()  # username/email/phone
        password = request.POST.get('password', '').strip()

        # -------------------------
        # 1️⃣ Find user
        # -------------------------
        try:
            user_obj = CustomUser.objects.get(
                Q(username=identifier) |
                Q(email=identifier) |
                Q(phone=identifier)
            )
        except CustomUser.DoesNotExist:
            messages.error(request, "Invalid credentials")
            return render(request, 'login.html')

        # -------------------------
        # 1.5️⃣ Check if user has a password
        # -------------------------
        if not user_obj.has_usable_password():
            request.session["set_password_user_id"] = user_obj.id
            messages.info(request, "Please set your password to continue.")
            return redirect("set_google_password")

        # -------------------------
        # 2️⃣ Authenticate user
        # -------------------------
        user = authenticate(request, username=user_obj.username, password=password)
        if user is None:
            messages.error(request, "Invalid credentials")
            return render(request, 'login.html')

        # -------------------------
        # 3️⃣ Device fingerprint
        # -------------------------
        ip = get_client_ip(request)
        device_name = get_device_name(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # -------------------------
        # 4️⃣ Trusted device → log in directly
        # -------------------------
        if TrustedDevice.objects.filter(
            user=user, device_name=device_name, ip_address=ip
        ).exists():
            login(request, user)
            return redirect('admin_dashboard' if user.is_superuser else 'dashboard')

        # -------------------------
        # 5️⃣ New device → store pending info for verification
        # -------------------------
        request.session.flush()  # remove any previous auth session data

        request.session.update({
            "pending_user_id": user.id,
            "pending_ip": ip,
            "pending_ua": user_agent,
            "pending_name": device_name,
        })

        # User is NOT logged in yet
        return redirect("choose_verification_method")

    # -------------------------
    # 6️⃣ GET request → Show login page
    # -------------------------
    return render(request, 'login.html')


#User Logout

def logout_view(request):
    logout(request)
    return redirect('logout_success')

# Logout success message
def logout_success(request):
    return render(request, 'logout_success.html')

# Dashboard
@login_required
def dashboard(request):
    user = request.user

    # Count unread chat messages
    unread_messages_count = get_unread_messages(user)

    # Count standard notifications for this user
    notifications_count = Notification.objects.filter(user=user, is_read=False).count()

    # Total notifications (notifications + unread messages)
    total_notifications = notifications_count + unread_messages_count

    # If admin, redirect to admin dashboard
    if user.is_superuser or getattr(user, "role", None) == "admin":
        return redirect("admin_dashboard")

    # Applicant dashboard
    if getattr(user, "role", None) == "applicant":
        applications = Application.objects.filter(applicant=user)
        premium_jobs = applications.filter(job__is_premium=True).count()

        # Count deleted applications for Recycle Bin badge
        deleted_apps_count = applications.filter(is_deleted=True).count()

        return render(request, "applicant_dashboard.html", {
            "applications": applications,
            "premium_jobs": premium_jobs,
            "notifications_count": total_notifications,  # total notifications
            "deleted_apps_count": deleted_apps_count,    # Recycle Bin badge
        })

    # Employer dashboard
    elif getattr(user, "role", None) == "employer":
        posted_jobs_count = Job.objects.filter(employer=user).count()
        active_jobs = Job.objects.filter(employer=user, is_active=True).count()
        
        # Only count applications that are not soft-deleted by applicants
        applicants_count = Application.objects.filter(
            job__employer=user,
            is_deleted=False
        ).count()
    
        return render(request, "employer_dashboard.html", {
            "posted_jobs_count": posted_jobs_count,
            "active_jobs": active_jobs,
            "applicants_count": applicants_count,
            "notifications_count": total_notifications,  # total notifications
        })


    # Fallback → unknown role
    return redirect("login")

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
    job_id = request.GET.get("job_id")  # Check if employer is filtering for a specific job

    if job_id:
        # Show only applicants for the specific job, excluding soft-deleted for employer
        applicants = Application.objects.filter(
            job__id=job_id,
            job__employer=request.user,
            is_deleted_for_employer=False  # hide soft-deleted applications
        ).select_related("job", "applicant")

        applicants_count = applicants.count()
        jobs = Job.objects.filter(id=job_id, employer=request.user)  # just that job
    else:
        # Show applicants for ALL jobs posted by this employer
        jobs = Job.objects.filter(employer=request.user)
        applicants = Application.objects.filter(
            job__in=jobs,
            is_deleted_for_employer=False  # hide soft-deleted applications
        ).select_related("job", "applicant")
        applicants_count = applicants.count()

    return render(request, "view_applicants.html", {
        "jobs": jobs,
        "applicants": applicants,
        "applicants_count": applicants_count,
        "job_id": job_id,  # useful in template
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

            # --- Auto-set premium based on salary ---
            if job.salary and job.salary > 30000:
                job.is_premium = True
            else:
                job.is_premium = False
            # ---------------------------------------

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
                # send email
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

                # create in-app notification
                Notification.objects.create(
                    user=alert.user,
                    title="New Job Alert",
                    message=f"A new job '{job.title}' has been posted in {job.location}.",
                )
            # -----------------------------------------------------

            messages.success(request, "Job posted, email alerts & notifications sent.")
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

            # --- Auto-set premium based on salary ---
            if job.salary and job.salary > 30000:
                job.is_premium = True
            else:
                job.is_premium = False
            # ---------------------------------------

            job.save()

            messages.success(request, "Job updated successfully.")
            return redirect('dashboard')  # or job_detail page
    else:
        form = JobForm(instance=job)

    return render(request, 'edit_job.html', {'form': form, 'job': job})

# Apply Job View
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

            if created:
                # Notify employer
                Notification.objects.create(
                    user=job.employer,
                    title="New Job Application",
                    message=f"{request.user.username} has applied for your job '{job.title}'. (job_id={job.id})"
                )
                applied_status = 'yes'
                messages.success(request, f"✅ You have successfully applied to {job.title}!")
            else:
                applied_status = 'already'
                messages.info(request, f"ℹ️ You already applied for {job.title}.")

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
                        'product_data': {'name': f"Application Fee - {job.title}"},
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
            return render(request, 'apply_job.html', {'job': job, 'error': getattr(e, 'user_message', str(e))})
        except Exception as e:
            return render(request, 'apply_job.html', {'job': job, 'error': str(e)})

    # GET request for premium job → Show application page
    return render(request, 'apply_job.html', {'job': job})

@login_required
def apply_job_success(request, job_id, applied):
    """
    Display the job application status page.
    'applied' is 'yes' if the user just applied, 'already' if they applied before.
    """
    job = get_object_or_404(Job, pk=job_id)

    # Determine success boolean based on applied flag
    success = applied == "yes"

    # Render the status page without adding messages again
    return render(request, "apply_job_success.html", {
        "job": job,
        "success": success
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

@login_required
def job_detail(request, job_id):
    job = get_object_or_404(Job, id=job_id)

    # Default: no application
    application = None  

    # If user is an applicant, check if they already applied and not soft-deleted
    if request.user.role == "applicant":
        application = Application.objects.filter(
            job=job,
            applicant=request.user,
            is_deleted=False  # ignore soft-deleted applications
        ).first()

    context = {
        "job": job,
        "application": application,
    }
    return render(request, "job_detail.html", context)



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
    try:
        resume = Resume.objects.get(user=request.user)
    except Resume.DoesNotExist:
        return redirect('build_resume')  # redirect if resume not found

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
    resume = Resume.objects.filter(user=request.user).first()
    return render(request, 'view_resume.html', {'resume': resume})


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


from django.db.models import Count, Q, F

@login_required
def chat_view(request, application_id=None, job_id=None):
    """
    Unified chat view for both applicants and employers.
    - Applicants access via application_id
    - Employers access via job_id (with optional ?app_id= query param)
    - General landing if neither is provided
    Soft-deleted applications are hidden from the respective users.
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

    messages_list = []
    selected_app = None

    # -----------------------------
    # Case 1: Applicant chat
    # -----------------------------
    if application_id:
        app = get_object_or_404(
            Application.objects.select_related("job", "applicant", "job__employer"),
            id=application_id,
            is_deleted=False  # applicant should not see deleted apps
        )

        # Security check
        if user.id not in (app.applicant_id, app.job.employer_id):
            return redirect("job_detail", job_id=app.job_id)

        # Handle new message
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

        messages_list = app.messages.all().order_by("timestamp")
        selected_app = app

        # Mark employer messages as read when applicant views
        if user == app.applicant:
            ChatMessage.objects.filter(
                application=app,
                sender_id=app.job.employer_id,
                is_read=False
            ).update(is_read=True)

        context.update({
            "application": app,
            "messages": messages_list,
            "selected_app": selected_app,
        })

    # -----------------------------
    # Case 2: Employer chat (per job)
    # -----------------------------
    elif job_id:
        job = get_object_or_404(Job, id=job_id, employer=user)

        # Exclude applications hidden by applicant
        applications = job.applications.filter(is_deleted_for_employer=False).select_related("applicant").annotate(
            unread_count=Count(
                "messages",
                filter=Q(messages__is_read=False) & Q(messages__sender_id=F("applicant_id")),
            )
        )

        # Pick selected application
        selected_app_id = request.GET.get("app_id")
        if selected_app_id:
            try:
                selected_app_id = int(selected_app_id)
                selected_app = applications.filter(id=selected_app_id).first()
            except ValueError:
                selected_app = None

        if not selected_app:
            selected_app = applications.first() if applications else None

        # Handle new message
        if request.method == "POST" and selected_app:
            text = request.POST.get("message")
            if text:
                ChatMessage.objects.create(application=selected_app, sender=user, message=text)

                Notification.objects.create(
                    user=selected_app.applicant,
                    title="New Chat Message",
                    message=f"{user.username} (employer) sent you a new message about '{selected_app.job.title}'."
                )

        messages_list = selected_app.messages.all().order_by("timestamp") if selected_app else []

        # Mark applicant messages as read when employer views
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
            "messages": messages_list,
        })

    # -----------------------------
    # Case 3: General landing
    # -----------------------------
    else:
        if getattr(user, "is_employer", False):
            jobs = Job.objects.filter(employer=user).prefetch_related(
                "applications__applicant"
            )

            job = None
            applications = []
            selected_app = None
            messages_list = []

            # Pick job from query (?job_id=...)
            job_id_param = request.GET.get("job_id")
            if job_id_param:
                try:
                    job = jobs.filter(id=int(job_id_param)).first()
                except ValueError:
                    job = None

            # Default: first job if none chosen
            if not job and jobs.exists():
                job = jobs.first()

            if job:
                applications = job.applications.filter(is_deleted_for_employer=False).select_related("applicant").annotate(
                    unread_count=Count(
                        "messages",
                        filter=Q(messages__is_read=False) & Q(messages__sender_id=F("applicant_id")),
                    )
                )

                # Pick applicant (?app_id=...)
                selected_app_id = request.GET.get("app_id")
                if selected_app_id:
                    try:
                        selected_app = applications.filter(id=int(selected_app_id)).first()
                    except ValueError:
                        selected_app = None

                if not selected_app and applications.exists():
                    selected_app = applications.first()

                if selected_app:
                    messages_list = selected_app.messages.all().order_by("timestamp")

            context.update({
                "jobs": jobs,
                "job": job,
                "applications": applications,
                "selected_app": selected_app,
                "messages": messages_list,
            })

        else:
            # Applicant view: show all their applications except deleted
            applications = Application.objects.filter(
                applicant=user,
                is_deleted=False
            ).select_related("job__employer")
            selected_app = None
            messages_list = []

            # Pick one if requested (?app_id=...)
            selected_app_id = request.GET.get("app_id")
            if selected_app_id:
                try:
                    selected_app = applications.filter(id=int(selected_app_id)).first()
                except ValueError:
                    selected_app = None

            if not selected_app and applications.exists():
                selected_app = applications.first()

            if selected_app:
                messages_list = selected_app.messages.all().order_by("timestamp")

            context.update({
                "applications": applications,
                "selected_app": selected_app,
                "messages": messages_list,
            })

    # -----------------------------
    # AJAX response
    # -----------------------------
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return JsonResponse({
            "messages": [
                {
                    "id": msg.id,
                    "sender_id": msg.sender_id,
                    "text": msg.message,
                    "created": msg.timestamp.strftime("%Y-%m-%d %H:%M"),
                }
                for msg in messages_list
            ],
            "selected_app_id": selected_app.id if selected_app else None
        })

    # Render always with chat.html
    return render(request, "chat.html", context)
 
                
# ======================================================
# VIEW APPLICANT'S JOB APPLICATIONS
# ======================================================


@login_required
def view_applications(request):
    """
    Show jobs the logged-in applicant has applied to
    with current status, and auto-delete expired soft-deleted applications.
    """
    if request.user.role != "applicant":
        messages.error(request, "❌ Only applicants can access this page.")
        return redirect("dashboard")

    # Auto-delete expired soft-deleted applications
    deleted_apps = Application.objects.filter(applicant=request.user, is_deleted=True)
    for app in deleted_apps:
        if app.is_expired():
            ChatMessage.objects.filter(application=app).delete()
            Notification.objects.filter(
                user=app.job.employer,
                message__icontains=f"{app.applicant.username}"
            ).delete()
            app.delete()

    # Fetch active (not deleted) applications
    applications = (
        Application.objects.filter(applicant=request.user, is_deleted=False)
        .select_related("job", "job__employer")
        .order_by("-applied_on")
    )

    return render(request, "view_applications.html", {
        "applications": applications,
        "applications_count": applications.count(),
        "deleted_apps": deleted_apps,
    })


# ======================================================
# DELETE APPLICATION (Soft delete)
# ======================================================
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import Application, Notification, ChatMessage

@login_required
def delete_application(request, app_id):
    """
    Soft delete an application for the applicant and hide it from the employer.
    Works with SweetAlert AJAX.
    """
    if request.method == "POST":
        app = get_object_or_404(Application, id=app_id, applicant=request.user)

        # -------------------------------
        # Soft delete for applicant
        # -------------------------------
        app.is_deleted = True
        app.deleted_on = timezone.now()
        
        # -------------------------------
        # Hide from employer
        # -------------------------------
        app.is_deleted_for_employer = True
        app.save()

        # -------------------------------
        # Remove related notifications and chat messages
        # -------------------------------
        Notification.objects.filter(
            user=app.job.employer,
            message__icontains=f"{app.applicant.username}"
        ).delete()

        ChatMessage.objects.filter(application=app).delete()

        return JsonResponse({
            "success": True,
            "message": "Application moved to Recycle Bin and hidden from employer."
        })

    return JsonResponse({
        "success": False,
        "message": "Invalid request."
    }, status=400)


# ======================================================
# UNDO DELETE APPLICATION
# ======================================================

@login_required
def undo_delete_application(request, app_id):
    """
    Restore a soft-deleted application for the applicant
    and make it visible again to the employer.
    """
    app = get_object_or_404(Application, id=app_id, applicant=request.user)

    # Restore for applicant
    app.is_deleted = False
    app.deleted_on = None

    # Restore visibility for employer
    app.is_deleted_for_employer = False
    app.save()

    messages.success(request, "Application restored successfully and is now visible to the employer!")
    return redirect("recycle_bin")


# ======================================================
# PERMANENT DELETE APPLICATION (Destroy)
# ======================================================
@login_required
def destroy_application(request, app_id):
    app = get_object_or_404(Application, id=app_id, applicant=request.user)

    ChatMessage.objects.filter(application=app).delete()
    Notification.objects.filter(user=app.job.employer).delete()
    app.delete()

    messages.success(request, "Application permanently deleted.")
    return redirect("recycle_bin")


# ======================================================
# RECYCLE BIN VIEW
# ======================================================
@login_required
def recycle_bin(request):
    """
    Show all soft-deleted applications for the logged-in applicant.
    Auto-delete expired applications (7+ days) permanently.
    """
    # Fetch soft-deleted applications
    deleted_apps = Application.objects.filter(applicant=request.user, is_deleted=True)

    # Auto-delete expired applications
    for app in deleted_apps:
        if app.is_expired():  # You should have this method in your Application model
            ChatMessage.objects.filter(application=app).delete()
            Notification.objects.filter(user=app.job.employer).delete()
            app.delete()

    # Re-fetch remaining deleted apps after auto-delete
    deleted_apps = Application.objects.filter(applicant=request.user, is_deleted=True)

    # Pass the same variable name the template expects
    return render(request, "recycle_bin.html", {
        "deleted_apps": deleted_apps
    })

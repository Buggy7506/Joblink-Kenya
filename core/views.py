# Django shortcuts & HTTP
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect, FileResponse, JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

# Django auth
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash, get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.contrib import messages

# Django core utilities
from django.core.mail import send_mail, get_connection, EmailMultiAlternatives
from django.core.files.base import ContentFile
from django.core.files.temp import NamedTemporaryFile
from django.core.exceptions import ObjectDoesNotExist

# Django templates
from django.template.loader import get_template, render_to_string

# Django utils
from django.utils import timezone
from django.db.models import Q
from django.conf import settings
from django.utils.timezone import now

# Third-party libraries
import pdfkit
import stripe
from weasyprint import HTML
import requests
import urllib.parse
import os
import re
from collections import namedtuple
from datetime import datetime, timedelta
import cloudinary.uploader

# Local apps
from .models import (
    JobAlert, ChatMessage, Application, Job, SkillResource, Resume, CVUpload, 
    JobPlan, JobPayment, Profile, Notification, TrustedDevice, DeviceVerification, CustomUser
)
from .forms import (
    EditProfileForm, UserForm, ProfileForm, JobForm, ResumeForm, 
    CVUploadForm, JobPlanSelectForm, CustomUserCreationForm, ChangeUsernamePasswordForm, AccountSettingsForm
)
from .utils import send_verification_email, send_whatsapp_otp, send_sms_otp, generate_code, get_client_ip, get_device_fingerprint


# Privacy Policy page
def privacy_policy(request):
    return render(request, "privacy_policy.html", {"now": timezone.now()})

# Terms of Service page
def terms_of_service(request):
    return render(request, "terms_of_service.html", {"now": timezone.now()})

# Learn More page
def learn_more(request):
    return render(request, "learn_more.html", {"now": timezone.now()})

# Cookies Policy page
def cookies_policy(request):
    return render(request, "cookies_policy.html", {"now": timezone.now()})


# def choose_verification_method(request):
#     """
#     Let user choose a verification method (Email / WhatsApp / SMS) for OTP.
#     User is retrieved from session since the device is not verified yet.
#     """

#     # 🚫 Block access unless verification is pending
#     if not request.session.get("pending_verification"):
#         messages.error(request, "Unauthorized access.")
#         return redirect("login")

#     # 🔐 Ensure user is NOT authenticated (only if they are not in verification process)
#     if request.user.is_authenticated:
#         logout(request)

#     # Check if session is valid
#     user_id = request.session.get("verify_device_user_id")
#     if not user_id:
#         messages.error(request, "Session expired. Please login again.")
#         return redirect("login")

#     # Retrieve the user from the database
#     user = get_object_or_404(CustomUser, id=user_id)
#     profile, _ = Profile.objects.get_or_create(user=user)

#     # Available methods for verification
#     options = []
#     if user.email:
#         options.append("email")

#     phone = getattr(profile, "phone", None)
#     if phone:
#         options.extend(["whatsapp", "sms"])

#     # If no methods are available, show an error
#     if not options:
#         messages.error(request, "No verification method available. Please contact support.")
#         return redirect("login")

#     # Handle POST request for method selection
#     if request.method == "POST":
#         method = request.POST.get("method")

#         # Ensure the selected method is valid
#         if method not in options:
#             messages.error(request, "Invalid verification method selected.")
#             return redirect("choose-verification-method")

#         # Save the selected method to session
#         request.session["verification_method"] = method

#         # Redirect to verify device page
#         return redirect("verify-device")

#     # Render the verification method selection page
#     return render(
#         request,
#         "choose_verification_method.html",
#         {
#             "user": user,
#             "profile": profile,
#             "options": options,
#             "selected_method": request.session.get("verification_method"),
#             "phone": phone,
#             "pending_verification": True,
#         },
#     )

# def resend_device_code(request):
#     """
#     Handle the logic for resending the device verification OTP.
#     Rate-limits requests to prevent abuse.
#     """
#     # 1️⃣ Retrieve user from session
#     user_id = request.session.get('verify_device_user_id')
#     if not user_id:
#         messages.error(request, "Session expired. Please login again.")
#         return redirect("login")

#     user = get_object_or_404(CustomUser, id=user_id)
#     profile, _ = Profile.objects.get_or_create(user=user)

#     # 2️⃣ Verify chosen method
#     method = request.session.get('verification_method', 'email')
#     if method not in ['email', 'whatsapp', 'sms']:
#         messages.error(request, "Invalid verification method.")
#         return redirect("verify-device")

#     # 3️⃣ Rate-limit OTP requests (30s cooldown)
#     last_otp_sent = request.session.get('last_otp_sent', None)
#     if last_otp_sent:
#         # Convert last_otp_sent back to datetime from string if it exists
#         last_otp_sent = datetime.strptime(last_otp_sent, "%Y-%m-%d %H:%M:%S")

#     now_time = datetime.now()
#     if last_otp_sent and now_time < last_otp_sent + timedelta(seconds=30):
#         remaining_time = (last_otp_sent + timedelta(seconds=30) - now_time).seconds
#         messages.error(request, f"Please wait {remaining_time} seconds before requesting a new OTP.")
#         return redirect("verify-device")

#     # 4️⃣ Generate OTP
#     otp_code = generate_code()  # your existing OTP generator function

#     device_fingerprint = request.session.get('device_fingerprint', 'unknown')
#     DeviceVerification.objects.update_or_create(
#         user=user,
#         device_fingerprint=device_fingerprint,
#         defaults={'code': otp_code, 'is_used': False, 'verified_via': method}
#     )

#     # 5️⃣ Send OTP
#     try:
#         if method == "email" and user.email:
#             send_mail(
#                 subject="Your JobLink Verification Code",
#                 message=f"Your verification code is: {otp_code}",
#                 from_email=settings.DEFAULT_FROM_EMAIL,
#                 recipient_list=[user.email],
#                 fail_silently=False,
#             )
#         elif method in ["sms", "whatsapp"]:
#             phone_number = profile.phone
#             if phone_number:
#                 # Replace print with actual SMS/WhatsApp sending logic
#                 print(f"OTP for {method.upper()} sent to {phone_number}: {otp_code}")
#             else:
#                 messages.error(request, f"No phone number available for {method.upper()}.")
#                 return redirect("verify-device")

#         # 6️⃣ Update last OTP sent time (store as string)
#         request.session['last_otp_sent'] = now_time.strftime("%Y-%m-%d %H:%M:%S")

#         messages.success(request, f"A new verification code has been sent via {method.upper()}.")
#     except Exception as e:
#         messages.error(request, f"Failed to send OTP: {str(e)}")

#     return redirect("verify-device")

# def verify_device(request):
#     """
#     Handle OTP verification for new devices.
#     User is NOT logged in until device verification completes.
#     """

#     # Ensure user is logged out and session auth cleared
#     if request.user.is_authenticated:
#         logout(request)
#         request.session.flush()

#     user_id = request.session.get("verify_device_user_id")
#     if not user_id:
#         messages.error(request, "Session expired. Please login again.")
#         return redirect("login")

#     # Use a SAFE variable name (NOT 'user')
#     pending_user = get_object_or_404(CustomUser, id=user_id)
#     profile, _ = Profile.objects.get_or_create(user=pending_user)

#     device_hash = get_device_fingerprint(request)
#     ip = get_client_ip(request)
#     method = request.session.get("verification_method", "email")

#     verification = DeviceVerification.objects.filter(
#         user=pending_user,
#         device_fingerprint=device_hash,
#         is_used=False
#     ).order_by("-created_at").first()

#     # Generate & send OTP if none exists
#     if not verification:
#         code = generate_code()
#         verification = DeviceVerification.objects.create(
#             user=pending_user,
#             device_fingerprint=device_hash,
#             user_agent=request.META.get("HTTP_USER_AGENT", ""),
#             ip_address=ip,
#             code=code
#         )

#         try:
#             if method == "email" and pending_user.email:
#                 send_mail(
#                     subject="Your JobLink Verification Code",
#                     message=f"Your verification code is: {code}",
#                     from_email=settings.DEFAULT_FROM_EMAIL,
#                     recipient_list=[pending_user.email],
#                     fail_silently=False,
#                 )

#             elif method == "sms" and profile.phone:
#                 print(f"SMS OTP sent to {profile.phone}: {code}")

#             elif method == "whatsapp" and profile.phone:
#                 print(f"WhatsApp OTP sent to {profile.phone}: {code}")

#             else:
#                 messages.error(request, "No contact method available.")
#                 return redirect("verify-device")

#         except Exception:
#             messages.error(request, "Failed to send OTP.")
#             return redirect("verify-device")

#     # Validate OTP
#     if request.method == "POST":
#         entered_code = request.POST.get("otp", "").strip()

#         if verification and entered_code == verification.code:
#             verification.is_used = True
#             verification.verified_via = method
#             verification.save()

#             TrustedDevice.objects.update_or_create(
#                 user=pending_user,
#                 device_fingerprint=device_hash,
#                 defaults={
#                     "user_agent": request.META.get("HTTP_USER_AGENT", ""),
#                     "ip_address": ip,
#                     "verified": True,
#                 }
#             )

#             messages.success(
#                 request,
#                 "Device verified successfully. Please log in."
#             )
#             return redirect("login")

#         messages.error(request, "Invalid OTP. Please try again.")

#     # DO NOT pass `user` into template
#     return render(request, "verify_device.html", {
#         "method": method,
#         "profile": profile,
#         "pending_user": pending_user,  # ✅ SAFE
#     })

@login_required
@require_POST
def delete_cv(request):
    user = request.user
    # Get the latest CV
    latest_cv = CVUpload.objects.filter(applicant=user).order_by('-id').first()

    if latest_cv:
        # Delete from Cloudinary if public_id exists
        public_id = getattr(latest_cv.cv, 'public_id', None)
        if public_id:
            try:
                cloudinary.uploader.destroy(public_id)
            except Exception:
                pass  # optionally log the error

        # Delete from Django storage
        latest_cv.cv.delete(save=False)
        # Delete the CV record
        latest_cv.delete()

    return JsonResponse({'status': 'deleted'})
    

@login_required
def quick_profile_update(request):
    user = request.user

    # Base context for modal reopening and errors
    context = {
        "user": user,
        "skills": user.skills.split(",") if user.skills else [],
        "user_cv": CVUpload.objects.filter(applicant=user).order_by('-id').first(),
        "form_errors": {},
        "modal_type": None,
    }

    if request.method == "POST":
        modal_type = request.POST.get("modal_type")
        context["modal_type"] = modal_type
        errors = {}

        # ---------- PHONE ----------
        if modal_type == "phone":
            phone = request.POST.get("phone", "").strip()
            if not phone:
                errors["phone"] = ["Phone number is required."]
            else:
                user.phone = phone

        # ---------- LOCATION ----------
        elif modal_type == "location":
            location = request.POST.get("location", "").strip()
            if not location:
                errors["location"] = ["Location is required."]
            else:
                user.location = location

        # ---------- SKILLS ----------
        elif modal_type == "skills":
            skills = request.POST.get("skills", "").strip()
            if not skills:
                errors["skills"] = ["Please add at least one skill."]
            else:
                user.skills = skills

        # ---------- CV UPLOAD ----------
        elif modal_type == "upload_cv":
            cv_file = request.FILES.get("upload_cv")
            if not cv_file:
                errors["upload_cv"] = ["Please upload a CV."]
            else:
                # Create a new CV record every time
                CVUpload.objects.create(applicant=user, cv=cv_file)
                # Update latest CV in context
                context["user_cv"] = CVUpload.objects.filter(applicant=user).order_by('-id').first()

        # ---------- PROFILE PIC DELETE ----------
        elif modal_type == "profile_pic_delete":
            if user.profile_pic:
                try:
                    cloudinary.uploader.destroy(user.profile_pic.public_id)
                except Exception:
                    pass
                user.profile_pic = None
                user.save()
            return JsonResponse({"status": "deleted"})

        # ---------- PROFILE PIC UPLOAD ----------
        elif modal_type == "profile_pic":
            pic = request.FILES.get("profile_pic")
            if not pic:
                errors["profile_pic"] = ["No image selected."]
            else:
                user.profile_pic = pic

        # ---------- HANDLE VALIDATION ERRORS ----------
        if errors:
            context["form_errors"] = errors
            return render(request, "profile.html", context)

        # ---------- SAVE USER ----------
        user.save()
        return redirect("profile")

    # Fallback for GET requests
    return redirect("profile")

@login_required
def account_settings(request):
    """
    Handles username + password update
    """
    user = request.user

    if request.method == "POST":
        form = AccountSettingsForm(user=user, data=request.POST)

        if form.is_valid():
            form.save()
            update_session_auth_hash(request, user)  # keep user logged in
            messages.success(request, "Account details updated successfully.")
            return redirect("account_settings")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = AccountSettingsForm(user=user)

    return render(request, "change_username_password.html", {
        "form": form
    })


@login_required
def delete_account(request):
    """
    Requires password re-entry before deletion.
    """
    if request.method != "POST":
        return redirect(reverse("account_settings"))

    password = request.POST.get("password")
    user = authenticate(username=request.user.username, password=password)

    if user is None:
        messages.error(request, "Incorrect password. Account not deleted.")
        return redirect(f"{reverse('account_settings')}#danger")

    # Delete user and log out
    user.delete()
    logout(request)
    messages.success(request, "Your account has been permanently deleted.")
    return redirect(reverse("login"))



def set_google_password(request):
    """
    Google OAuth users must set a password.
    """
    google_user = request.session.get('google_user')
    if not google_user:
        messages.error(request, "Session expired. Please login with Google again.")
        return redirect('signup')

    # Pre-fill first name for template
    first_name = google_user.get('first_name', '')

    if request.method == 'POST':
        password = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        # -------------------------
        # 1️⃣ Validate inputs
        # -------------------------
        if not password or not confirm_password:
            messages.error(request, "Both password fields are required.")
            return render(request, 'set_google_password.html', {'user': google_user})

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'set_google_password.html', {'user': google_user})

        # Strong password rules
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return render(request, 'set_google_password.html', {'user': google_user})

        if not re.search(r'[A-Z]', password):
            messages.error(request, "Password must contain an uppercase letter.")
            return render(request, 'set_google_password.html', {'user': google_user})

        if not re.search(r'\d', password):
            messages.error(request, "Password must contain a number.")
            return render(request, 'set_google_password.html', {'user': google_user})

        if not re.search(r'[@$!%*#?&]', password):
            messages.error(request, "Password must contain a special character.")
            return render(request, 'set_google_password.html', {'user': google_user})

        # -------------------------
        # 2️⃣ Prevent duplicate email
        # -------------------------
        email = google_user['email']
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "An account with this email already exists. Please log in.")
            return redirect('login')

        # -------------------------
        # 3️⃣ Create user
        # -------------------------
        last_name = google_user.get('last_name', '')
        role = request.session.get('google_role')

        # Username generation
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
            role=role,
        )
        user.set_password(password)
        user.save()

        # Optional: Save Google profile picture
        picture_url = google_user.get('picture')
        if picture_url:
            try:
                response = requests.get(picture_url, timeout=5)
                if response.status_code == 200:
                    user.profile_pic.save(
                        f"{username}_google.jpg",
                        ContentFile(response.content),
                        save=True
                    )
            except Exception:
                pass

        # -------------------------
        # 4️⃣ Login + cleanup
        # -------------------------
        login(request, user)
        request.session.pop('google_user', None)
        request.session.pop('google_role', None)

        messages.success(request, "Account created successfully!")
        return redirect('dashboard')

    # GET request
    return render(request, 'set_google_password.html', {'user': google_user})


# Google OAuth settings
GOOGLE_CLIENT_ID = '268485346186-pocroj4v0e6dhdufub2m4vaji0ts3ohj.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_REDIRECT_URI = 'https://stepper.dpdns.org/google/callback/'
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

def login_view(request):
    """
    Login view with device verification:
    - Username / Email / Phone
    - Device verification via Email / WhatsApp / SMS
    """

    # ❌ Clear stale verification sessions (DEVICE VERIFICATION)
    # request.session.pop("verify_device_user_id", None)
    # request.session.pop("verification_method", None)
    # request.session.pop("pending_verification", None)

    if request.method == 'POST':
        identifier = request.POST.get('identifier', '').strip()
        password = request.POST.get('password', '').strip()

        # 1️⃣ Find user
        try:
            user_obj = CustomUser.objects.get(
                Q(username=identifier) |
                Q(email=identifier) |
                Q(phone=identifier)
            )
        except CustomUser.DoesNotExist:
            messages.error(request, "Invalid credentials")
            return render(request, 'login.html')

        # Ensure profile exists
        Profile.objects.get_or_create(user=user_obj)

        # 2️⃣ Google users → force password setup
        if not user_obj.has_usable_password():
            request.session["set_password_user_id"] = user_obj.id
            messages.info(request, "Please set your password to continue.")
            return redirect("set_google_password")

        # 3️⃣ Authenticate credentials
        user = authenticate(
            request,
            username=user_obj.username,
            password=password
        )

        if user is None:
            messages.error(request, "Invalid credentials")
            return render(request, 'login.html')

        # ❌ DEVICE TRUST CHECK (DISABLED)
        # device_hash = get_device_fingerprint(request)
        # device = TrustedDevice.objects.filter(
        #     user=user,
        #     device_fingerprint=device_hash,
        #     verified=True
        # ).first()

        # ❌ UNTRUSTED DEVICE VERIFICATION FLOW (DISABLED)
        # if not device:
        #     ip = get_client_ip(request)
        #
        #     DeviceVerification.objects.get_or_create(
        #         user=user,
        #         device_fingerprint=device_hash,
        #         is_used=False,
        #         defaults={
        #             "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        #             "ip_address": ip,
        #             "code": generate_code(),
        #         }
        #     )
        #
        #     logout(request)
        #
        #     request.session["verify_device_user_id"] = user.id
        #     request.session["pending_verification"] = True
        #
        #     return redirect("choose-verification-method")

        # ✅ DIRECT LOGIN (DEVICE VERIFICATION BYPASSED)
        login(request, user)

        # ❌ Cleanup verification flags (DEVICE VERIFICATION)
        # request.session.pop("pending_verification", None)

        return redirect(
            'admin_dashboard' if user.is_superuser else 'dashboard'
        )

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

    if request.method == "POST":
        # Handle profile updates
        form = ProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()

            # Handle CV upload
            if 'upload_cv' in request.FILES:
                CVUpload.objects.create(applicant=user, cv=request.FILES['upload_cv'])

            return redirect('profile')  # reload page to reflect updates
    else:
        form = ProfileForm(instance=user)

    # Get the latest CV
    user_cv = CVUpload.objects.filter(applicant=user).order_by('-id').first()

    # Convert skills string from CustomUser to a list (comma-separated)
    skills_list = [skill.strip() for skill in user.skills.split(',')] if user.skills else []

    context = {
        'user': user,
        'user_cv': user_cv,
        'skills': skills_list,
        'profile_picture_url': user.profile_pic.url if user.profile_pic else None,
        'form': form,
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

@login_required
def edit_profile(request):
    # Ensure the Profile object exists
    profile, _ = Profile.objects.get_or_create(user=request.user)

    # Get the latest CV for this user (if any)
    latest_cv = CVUpload.objects.filter(applicant=request.user).order_by('-id').first()
    if latest_cv and latest_cv.cv:
        # Extract filename from Cloudinary URL
        cv_filename = os.path.basename(latest_cv.cv.url)
    else:
        cv_filename = None

    if request.method == 'POST':
        form = EditProfileForm(request.POST, request.FILES, instance=request.user, user=request.user)

        if form.is_valid():
            user = form.save(commit=False)

            # Update profile picture
            if 'profile_pic' in request.FILES:
                profile.profile_pic = request.FILES['profile_pic']
                profile.save()

            user.save()  # Save other user fields

            # Redirect based on user role
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
        'profile_picture_url': profile.profile_pic.url if profile.profile_pic else None,
        'user_cv': latest_cv,
        'cv_filename': cv_filename,
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

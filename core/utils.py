# core/utils.py
import hashlib
import logging
import secrets
import requests
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps
from django.core.files.base import ContentFile

from sib_api_v3_sdk import ApiClient, Configuration, TransactionalEmailsApi, SendSmtpEmail

from .models import DeviceVerification

logger = logging.getLogger(__name__)

# ======================================================
# OTP / SECURITY
# ======================================================

def generate_code():
    """Generate a cryptographically secure 6-digit OTP"""
    return f"{secrets.randbelow(900000) + 100000}"


def otp_recently_sent(identifier, fingerprint):
    return DeviceVerification.objects.filter(
        email=identifier,
        device_fingerprint=fingerprint,
        created_at__gte=timezone.now() - timedelta(seconds=settings.OTP_RESEND_COOLDOWN)
    ).exists()


# ======================================================
# BREVO EMAIL (ONLY EMAIL PROVIDER)
# ======================================================
def brevo_send_email(subject, recipient, html_content):
    """
    Send transactional email using Brevo shared sender
    """
    config = Configuration()
    config.api_key["api-key"] = settings.BREVO_API_KEY

    client = ApiClient(config)
    api = TransactionalEmailsApi(client)

    email = SendSmtpEmail(
        sender={
            "name": "Joblink Kenya",
            "email": "support@stepper.dpdns.org",  # ✅ REQUIRED by Brevo
        },
        to=[{"email": recipient}],
        subject=subject,
        html_content=html_content,
        reply_to={
            "email": "support@stepper.dpdns.org",
            "name": "Joblink Kenya Support"
        }
    )

    return api.send_transac_email(email)

def send_otp_email(email, code):
    return brevo_send_email(
        subject="Your Joblink Kenya Login Code",
        recipient=email,
        html_content=f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:20px">
            <h2 style="color:#0f172a">Joblink Kenya</h2>

            <p>Your one-time login code is:</p>

            <div style="
                font-size:32px;
                font-weight:bold;
                letter-spacing:6px;
                margin:20px 0;
                text-align:center;
            ">
                {code}
            </div>

            <p><strong>This code expires in {settings.OTP_EXPIRY_MINUTES} minutes.</strong></p>

            <p style="color:#475569;font-size:14px">
                If you did not request this login, you can safely ignore this email.
            </p>

            <hr style="margin-top:30px;border:none;border-top:1px solid #e5e7eb">

            <p style="font-size:12px;color:#64748b">
                Joblink Kenya • Secure Authentication
            </p>
        </div>
        """
    )
    
# ======================================================
# EMPLOYER ACCESS GUARD
# ======================================================

def employer_verified_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        profile = getattr(request.user, "profile", None)

        if request.user.is_authenticated and profile and profile.role == "employer":
            company = getattr(request.user, "employer_company", None)
            if company and company.status == "pending":
                messages.warning(
                    request,
                    "You must upload verification documents first."
                )
                return redirect("upload_company_docs")

        return view_func(request, *args, **kwargs)
    return wrapper


# ======================================================
# BUSINESS EMAIL VALIDATION
# ======================================================

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com",
    "hotmail.com", "icloud.com", "aol.com",
}

def is_business_email(email: str) -> bool:
    if not email or "@" not in email:
        return False
    domain = email.split("@")[-1].lower()
    return domain not in FREE_EMAIL_DOMAINS


# ======================================================
# GOOGLE PROFILE PICTURE
# ======================================================

def save_google_profile_picture(backend, user, response, *args, **kwargs):
    if backend.name == "google-oauth2":
        picture_url = response.get("picture")
        if picture_url and not user.profile_pic:
            try:
                resp = requests.get(picture_url, timeout=10)
                if resp.status_code == 200:
                    user.profile_pic.save(
                        f"{user.username}_google.jpg",
                        ContentFile(resp.content),
                        save=True
                    )
            except Exception as e:
                logger.warning(f"Google profile image save failed: {e}")


# ======================================================
# DEVICE / IP / LOCATION
# ======================================================

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    real_ip = request.META.get("HTTP_X_REAL_IP")
    if real_ip:
        return real_ip.strip()

    return request.META.get("REMOTE_ADDR", "")


def get_device_fingerprint(request):
    ua = request.META.get("HTTP_USER_AGENT", "")
    ip = get_client_ip(request)
    raw = f"{ua}|{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def get_location_from_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            city = data.get("city", "")
            country = data.get("country", "")
            return f"{city}, {country}" if city else country
    except Exception as e:
        logger.warning(f"IP location lookup failed: {e}")
    return ""


# ======================================================
# BREVO (SMS)
# ======================================================
def send_sms_infini(phone, message):
    """
    Brevo transactional SMS sender.
    Function name kept for backward compatibility.
    """

    url = "https://api.brevo.com/v3/transactionalSMS/sms"

    payload = {
        "sender": "JOBLINK",         
        "recipient": phone,             
        "content": message,
        "type": "transactional"
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": settings.BREVO_SMS_API_KEY
    }

    response = requests.post(
        url,
        json=payload,
        headers=headers,
        timeout=15
    )

    response.raise_for_status()
    return response.json()    

# ======================================================
# CALLMEBOT (WHATSAPP - FREE)
# ======================================================

def send_whatsapp_callmebot(phone, message):
    api_key = getattr(settings, "CALLMEBOT_API_KEY", "")
    if not api_key:
        raise ValueError("CALLMEBOT_API_KEY is required for WhatsApp OTP.")

    response = requests.get(
        "https://api.callmebot.com/whatsapp.php",
        params={
            "phone": phone,
            "text": message,
            "apikey": api_key,
        },
        timeout=15,
    )
    response.raise_for_status()
    return {"status": "queued", "response": response.text}


# ======================================================
# UNIFIED OTP DISPATCHER
# ======================================================

def send_otp(channel, destination, code):
    message = f"Your Joblink verification code is {code}. Valid for {settings.OTP_EXPIRY_MINUTES} minutes."

    if channel == "sms":
        return send_sms_infini(destination, message)

    if channel == "whatsapp":
        return send_whatsapp_callmebot(destination, message)

    if channel == "email":
        return send_otp_email(destination, code)

    raise ValueError("Invalid OTP channel")

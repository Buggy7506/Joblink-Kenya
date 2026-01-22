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

from twilio.rest import Client
from sib_api_v3_sdk import ApiClient, Configuration, TransactionalEmailsApi, SendSmtpEmail

from .models import DeviceVerification

logger = logging.getLogger(__name__)

# ======================================================
# OTP / SECURITY
# ======================================================

def generate_code():
    """Generate a cryptographically secure 6-digit OTP"""
    return f"{secrets.randbelow(900000) + 100000}"


def otp_recently_sent(email, fingerprint):
    return DeviceVerification.objects.filter(
        email=email,
        device_fingerprint=fingerprint,
        created_at__gte=timezone.now() - timedelta(seconds=settings.OTP_RESEND_COOLDOWN)
    ).exists()


# ======================================================
# BREVO EMAIL (ONLY EMAIL PROVIDER)
# ======================================================

def brevo_send_email(subject, html_content, recipient):
    """
    Send transactional email using Brevo shared sender.
    DO NOT set sender.email (important for deliverability).
    """
    config = Configuration()
    config.api_key["api-key"] = settings.BREVO_API_KEY

    with ApiClient(config) as client:
        api = TransactionalEmailsApi(client)

        email = SendSmtpEmail(
            sender={"name": "Joblink Kenya"},
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
    """OTP email wrapper"""
    return brevo_send_email(
        subject="Your Joblink Kenya login code",
        recipient=email,
        html_content=f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto">
            <h2>Joblink Kenya</h2>
            <p>Your one-time login code is:</p>
            <h1 style="letter-spacing:4px">{code}</h1>
            <p><b>This code expires in {settings.OTP_EXPIRY_MINUTES} minutes.</b></p>
            <p>If you did not request this, you can safely ignore this email.</p>
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
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "aol.com",
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
# TWILIO — WHATSAPP / SMS
# ======================================================

def send_whatsapp_otp(phone, code):
    try:
        client = Client(
            settings.TWILIO_ACCOUNT_SID,
            settings.TWILIO_AUTH_TOKEN
        )
        message = client.messages.create(
            body=f"Joblink Kenya OTP: {code}",
            from_=settings.TWILIO_WHATSAPP_NUMBER,
            to=f"whatsapp:{phone}"
        )
        logger.info(f"WhatsApp OTP sent to {phone} ({message.sid})")
        return True
    except Exception as e:
        logger.error(f"WhatsApp OTP failed: {e}")
        return False


def send_sms_otp(phone, code):
    try:
        client = Client(
            settings.TWILIO_ACCOUNT_SID,
            settings.TWILIO_AUTH_TOKEN
        )
        message = client.messages.create(
            body=f"Joblink Kenya OTP: {code}",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone
        )
        logger.info(f"SMS OTP sent to {phone} ({message.sid})")
        return True
    except Exception as e:
        logger.error(f"SMS OTP failed: {e}")
        return False

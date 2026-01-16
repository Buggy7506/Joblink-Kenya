# core/utils.py
import hashlib
import logging
import os
import secrets
import requests
from twilio.rest import Client
from django.conf import settings
from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps
from django.core.files.base import ContentFile
import time
import secrets

logger = logging.getLogger(__name__)

def long():
    return secrets.token_urlsafe(12)

def employer_verified_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        profile = getattr(request.user, "profile", None)

        if request.user.is_authenticated and profile and profile.role == "employer":
            company = getattr(request.user, "employercompany", None)
            if company and company.status == "pending":
                messages.warning(
                    request,
                    "You must upload verification documents first."
                )
                return redirect("upload_company_docs")

        return view_func(request, *args, **kwargs)
    return wrapper

# =========================
# Business email validation
# =========================

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

def save_google_profile_picture(backend, user, response, *args, **kwargs):
    """
    Save the Google profile picture to user's profile on signup/login
    """
    if backend.name == 'google-oauth2':
        picture_url = response.get('picture')
        if picture_url and not user.profile_pic:  # avoid overwriting if user already has one
            try:
                resp = requests.get(picture_url)
                if resp.status_code == 200:
                    user.profile_pic.save(
                        f"{user.username}_google.jpg",
                        ContentFile(resp.content),
                        save=True
                    )
            except Exception as e:
                print("Error saving Google profile picture:", e)


# ---------------------------
# Device Fingerprint & IP
# ---------------------------
def get_client_ip(request):
    """
    Get the real client IP, handling proxies (Cloudflare/Nginx).
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    
    real_ip = request.META.get('HTTP_X_REAL_IP')
    if real_ip:
        return real_ip.strip()

    return request.META.get('REMOTE_ADDR', '')


def get_device_fingerprint(request):
    """
    Returns a hashed fingerprint representing the device.
    Combines IP and User-Agent for stable device identity.
    """
    ua = request.META.get('HTTP_USER_AGENT', '')
    ip = get_client_ip(request)
    raw = f"{ua}|{ip}"
    # Hash → 32-character fingerprint
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ---------------------------
# Location Lookup
# ---------------------------
def get_location_from_ip(ip):
    """
    Get approximate location (city, country) from IP using ipinfo.io API.
    Free plan has rate limits.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            city = data.get("city", "")
            country = data.get("country", "")
            return f"{city}, {country}" if city else country
    except Exception as e:
        logger.warning(f"Failed to get location for IP {ip}: {e}")
    return ""


# ---------------------------
# OTP / Verification Code
# ---------------------------
def generate_code():
    """Generate a cryptographically secure 6-digit verification code."""
    return f"{secrets.randbelow(900000) + 100000}"  # 100000–999999


# ---------------------------
# SendGrid Email
# ---------------------------
def send_verification_email(email, code, max_retries=3):
    """
    Sends a device verification code using SendGrid API.
    Works on cloud platforms like Render where SMTP may be blocked.
    """
    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
    if not SENDGRID_API_KEY:
        logger.error("SENDGRID_API_KEY is not set in environment variables.")
        return False

    payload = {
        "personalizations": [
            {"to": [{"email": email}], "subject": "Your Device Verification Code"}
        ],
        "from": {"email": "security@stepper.dpdns.org", "name": "Stepper"},
        "content": [
            {
                "type": "text/html",
                "value": f"""
                <div style="font-family:Arial,sans-serif; line-height:1.6">
                    <h2>Device Verification</h2>
                    <p>Your verification code is:</p>
                    <h1 style="letter-spacing:4px;">{code}</h1>
                    <p>This code expires in <strong>10 minutes</strong>.</p>
                    <p>If you did not request this, please secure your account immediately.</p>
                </div>
                """
            }
        ],
    }

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={
                    "Authorization": f"Bearer {SENDGRID_API_KEY}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=10,
            )
            if response.status_code == 202:
                logger.info(f"Verification email sent successfully to {email}")
                return True
            else:
                logger.warning(
                    f"Attempt {attempt}: Failed to send email to {email} - "
                    f"Status {response.status_code}, Response: {response.text}"
                )
        except requests.RequestException as e:
            logger.warning(f"Attempt {attempt}: Network error sending email to {email}: {e}")

        time.sleep(2)

    logger.error(f"All attempts failed. Could not send verification email to {email}.")
    return False


# ---------------------------
# Twilio WhatsApp / SMS
# ---------------------------
def send_whatsapp_otp(phone, code):
    """
    Send OTP via WhatsApp using Twilio.
    """
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f"Stepper OTP: {code}",
            from_=settings.TWILIO_WHATSAPP_NUMBER,
            to=f"whatsapp:{phone}"
        )
        logger.info(f"WhatsApp OTP sent to {phone}: SID {message.sid}")
        return True
    except Exception as e:
        logger.error(f"Failed to send WhatsApp OTP to {phone}: {e}")
        return False


def send_sms_otp(phone, code):
    """
    Send OTP via SMS using Twilio.
    """
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f"Stepper OTP: {code}",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone
        )
        logger.info(f"SMS OTP sent to {phone}: SID {message.sid}")
        return True
    except Exception as e:
        logger.error(f"Failed to send SMS OTP to {phone}: {e}")
        return False

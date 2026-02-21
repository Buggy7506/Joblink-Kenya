# core/utils.py
import hashlib
import time
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




def send_verification_email(email, code):
    """Backward-compatible wrapper for device verification OTP emails."""
    return send_otp_email(email, code)


def send_whatsapp_otp(phone, code):
    """Send OTP using WhatsApp channel via TextMeBot."""
    return send_textmebot_message(phone, message=f"Your Joblink Kenya verification code is: {code}")


def send_sms_otp(phone, code):
    """Send OTP using SMS channel via TextMeBot."""
    return send_textmebot_message(phone, message=f"Your Joblink Kenya verification code is: {code}")
    
def build_branded_email(title, body_html, footer_text="Joblink Kenya • Secure Authentication"):
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:20px">
        <h2 style="color:#0f172a">Joblink Kenya</h2>

        <h3 style="color:#0f172a;margin-bottom:12px">{title}</h3>

        <div style="color:#0f172a;font-size:15px;line-height:1.6">
            {body_html}
        </div>

        <hr style="margin-top:30px;border:none;border-top:1px solid #e5e7eb">

        <p style="font-size:12px;color:#64748b">
            {footer_text}
        </p>
    </div>
    """
    
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
# TEXTMEBOT (SMS + WHATSAPP)
# ======================================================
def send_textmebot_message(phone, message="", image_url=None, document_url=None):
    """
    Send messages via TextMeBot (SMS or WhatsApp).

    Parameters:
        phone (str): Recipient phone number with country code (e.g., +254712345678)
        message (str): Text message to send
        image_url (str, optional): URL of an image to send
        document_url (str, optional): URL of a PDF or document to send

    Returns:
        dict: Status and API response
    """

    api_key = getattr(settings, "TEXTMEBOT_API_KEY", "")
    if not api_key:
        raise ValueError("TEXTMEBOT_API_KEY is required for sending messages.")

    url = "http://api.textmebot.com/send.php"

    params = {
        "recipient": phone,
        "apikey": api_key,
    }

    if message:
        params["text"] = message
    if image_url:
        params["file"] = image_url
    if document_url:
        params["document"] = document_url

    response = requests.get(url, params=params, timeout=15)
    response.raise_for_status()

    return {"status": "queued", "response": response.text}


# Configure logger for OTPs
logger = logging.getLogger("otp_logger")
if not logger.handlers:
    handler = logging.FileHandler("otp_logs.log")
    formatter = logging.Formatter("%(asctime)s - %(channel)s - %(destination)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ======================================================
# UNIFIED OTP DISPATCHER (SAFE)
# ======================================================
def send_otp(channel, destination, code):
    """
    Send OTP via SMS, WhatsApp, or Email with safety measures.

    Parameters:
        channel (str): "sms", "whatsapp", or "email"
        destination (str): Phone number or email address
        code (str/int): OTP code

    Returns:
        dict: API response
    """

    message = f"Your Joblink verification code is {code}. Valid for {settings.OTP_EXPIRY_MINUTES} minutes."

    try:
        # Send via SMS or WhatsApp using TextMeBot
        if channel in ("sms", "whatsapp"):
            response = send_textmebot_message(destination, message)

            # Log the OTP send
            logger.info(
                message,
                extra={"channel": channel, "destination": destination}
            )

            # Minimum 5-second delay to avoid WhatsApp blocks
            time.sleep(5)
            return {"ok": True, "response": response}

        # Send via email
        if channel == "email":
            response = send_otp_email(destination, code)

            # Log the email send
            logger.info(
                f"OTP sent via email: {code}",
                extra={"channel": channel, "destination": destination}
            )
            return {"ok": True, "response": response}

        raise ValueError("Invalid OTP channel")
    except Exception as exc:
        logger.exception(
            "Failed to send OTP",
            extra={"channel": channel, "destination": destination}
        )
        return {"ok": False, "error": str(exc)}

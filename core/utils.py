import hashlib
import logging
import os
import secrets
import requests
from twilio.rest import Client
from django.conf import settings

logger = logging.getLogger(__name__)

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
        "from": {"email": "security@stepper.dpdns.org", "name": "JobLink Kenya"},
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

        # small delay before retrying
        import time; time.sleep(2)

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

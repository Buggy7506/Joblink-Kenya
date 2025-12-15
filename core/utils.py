import random
import hashlib
from django.core.mail import EmailMessage, get_connection
from django.conf import settings
import logging
import os
import requests


logger = logging.getLogger(__name__)

def send_verification_email_smtp(email, code):
    """
    Sends a device verification code using Resend Email API (HTTPS).
    This works on Render and other cloud platforms where SMTP is blocked.
    """
    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {os.environ.get('RESEND_API_KEY')}",
                "Content-Type": "application/json",
            },
            json={
                "from": "JobLink Kenya <onboarding@resend.dev>",
                "to": [email],
                "subject": "Your Device Verification Code",
                "html": f"""
                    <div style="font-family:Arial,sans-serif; line-height:1.6">
                        <h2>Device Verification</h2>
                        <p>Your verification code is:</p>
                        <h1 style="letter-spacing:4px;">{code}</h1>
                        <p>This code expires in <strong>10 minutes</strong>.</p>
                        <p>If you did not request this, please secure your account.</p>
                    </div>
                """,
            },
            timeout=10,
        )

        if response.status_code not in (200, 201):
            logger.error(
                f"Failed to send verification email to {email}: "
                f"{response.status_code} - {response.text}"
            )
            return False

        logger.info(f"Verification email sent successfully to {email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send verification email to {email}: {e}")
        return False




def generate_code():
    """Generate a secure 6-digit verification code."""
    return f"{random.randint(100000, 999999)}"


def get_client_ip(request):
    """
    Get the real IP address from the request.
    Works behind proxies, Cloudflare, or Nginx reverse proxy.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # First IP in list is original client
        return x_forwarded_for.split(',')[0].strip()

    real_ip = request.META.get('HTTP_X_REAL_IP')
    if real_ip:
        return real_ip.strip()

    return request.META.get('REMOTE_ADDR', '')


def get_device_name(request):
    """
    Returns a hashed fingerprint representing the device.
    Prevents easy spoofing and ensures stable device identity.
    """
    ua = request.META.get('HTTP_USER_AGENT', '')
    ip = get_client_ip(request)

    raw = f"{ua}|{ip}"  # combine both for more reliability

    # Hash → 32 character fingerprint
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

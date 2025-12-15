import random
import hashlib
import logging
import os
import requests

logger = logging.getLogger(__name__)


def send_verification_email_sendgrid(email, code):
    """
    Sends a device verification code using SendGrid API.
    Works on Render and other cloud platforms where SMTP is blocked.
    """
    try:
        response = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": f"Bearer {os.environ.get('SENDGRID_API_KEY')}",
                "Content-Type": "application/json",
            },
            json={
                "personalizations": [
                    {"to": [{"email": email}], "subject": "Your Device Verification Code"}
                ],
                "from": {"email": "verified_sender@example.com", "name": "JobLink Kenya"},
                "content": [
                    {
                        "type": "text/html",
                        "value": f"""
                        <div style="font-family:Arial,sans-serif; line-height:1.6">
                            <h2>Device Verification</h2>
                            <p>Your verification code is:</p>
                            <h1 style="letter-spacing:4px;">{code}</h1>
                            <p>This code expires in <strong>10 minutes</strong>.</p>
                            <p>If you did not request this, please secure your account.</p>
                        </div>
                        """,
                    }
                ],
            },
            timeout=10,
        )

        if response.status_code not in (200, 202):
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

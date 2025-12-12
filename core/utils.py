import random
import hashlib
from django.core.mail import EmailMessage, get_connection
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def send_verification_email_smtp(email, code):
    """
    Sends a device verification code using Django SMTP email backend
    with explicit connection settings, ensuring it works in production.
    """
    subject = "Your Device Verification Code"
    message = (
        f"Your verification code is: {code}\n\n"
        "If you did not request this, please secure your account."
    )

    try:
        # Use explicit SMTP connection
        connection = get_connection(
            host=settings.EMAIL_HOST,
            port=settings.EMAIL_PORT,
            username=settings.EMAIL_HOST_USER,
            password=settings.EMAIL_HOST_PASSWORD,
            use_tls=settings.EMAIL_USE_TLS,
            fail_silently=False
        )

        email_msg = EmailMessage(
            subject=subject,
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email],
            connection=connection
        )

        email_msg.send()
        logger.info(f"Verification email sent successfully to {email}")
        return True

    except Exception as e:
        # Log error for debugging in production
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

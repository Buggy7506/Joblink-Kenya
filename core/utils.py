import random
import hashlib
import logging
import os
import requests
import time
import secrets


def send_sms(phone, code):
    url = "https://api.ng.termii.com/api/sms/send"
    payload = {
        "to": phone,
        "from": "JobLink",  # must be a verified Sender ID
        "sms": f"Your verification code is {code}",
        "type": "plain",
        "channel": "sms",  # or "sms" depending on your account
        "api_key": "TLwTTGPGXsziHFdFJyEikXGUtImhesDENtZKtLyzdtPtMtmUqDvuvNQwgFqRnb"
    }
    try:
        response = requests.post(url, json=payload)
        data = response.json()
        print("Termii response:", data)  # log for debugging
        return data
    except Exception as e:
        print("Error sending SMS:", e)
        return {"success": False, "error": str(e)}


logger = logging.getLogger(__name__)


def send_verification_email_sendgrid(email, code, max_retries=3):
    """
    Sends a device verification code using SendGrid API.
    Works on Render and other cloud platforms where SMTP is blocked.
    
    Args:
        email (str): Recipient email.
        code (str): Verification code.
        max_retries (int): Number of retry attempts for transient failures.

    Returns:
        bool: True if email was sent successfully, False otherwise.
    """
    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
    if not SENDGRID_API_KEY:
        logger.error("SENDGRID_API_KEY is not set in environment variables.")
        return False

    payload = {
        "personalizations": [
            {"to": [{"email": email}], "subject": "Your Device Verification Code"}
        ],
        "from": {"email": "linux7506@gmail.com", "name": "JobLink Kenya"},
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
            logger.warning(f"Attempt {attempt}: Network error while sending email to {email}: {e}")

        # small delay before retrying
        time.sleep(2)

    logger.error(f"All attempts failed. Could not send verification email to {email}.")
    return False


def generate_code():
    """Generate a cryptographically secure 6-digit verification code."""
    return f"{secrets.randbelow(900000) + 100000}"  # ensures 100000–999999


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

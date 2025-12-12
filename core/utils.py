import random
import hashlib


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

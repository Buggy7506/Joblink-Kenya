from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.contrib.auth import get_user_model
from .models import Profile, TrustedDevice, DeviceVerification
from .utils import (
    get_device_fingerprint,
    get_client_ip,
    get_location_from_ip,
    generate_code,
    send_verification_email,
    send_whatsapp_otp,
    send_sms_otp
)

User = get_user_model()


# -------------------------
# Profile creation signals
# -------------------------
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.get_or_create(user=instance)
        instance.profile.save()


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def save_profile(sender, instance, **kwargs):
    instance.profile.save()


# -------------------------
# New device detection signal
# -------------------------
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def detect_new_device(sender, instance, created, **kwargs):
    """
    Detects if the user logs in from a new device and triggers OTP verification.
    """
    if created:
        # Skip newly created users (first device doesn't need verification)
        return

    request = getattr(instance, "_request", None)
    if not request:
        # Must attach request in login view: user._request = request
        return

    device_hash = get_device_fingerprint(request)
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    location = get_location_from_ip(ip)

    # Check if device already exists
    device, created_device = TrustedDevice.objects.get_or_create(
        user=instance,
        device_fingerprint=device_hash,
        defaults={
            "user_agent": user_agent,
            "ip_address": ip,
            "location": location,
            "verified": False
        }
    )

    if not device.verified:
        # Avoid creating multiple OTPs for the same device
        existing_otp = DeviceVerification.objects.filter(
            user=instance,
            device_fingerprint=device_hash,
            is_used=False
        ).first()

        if existing_otp:
            code = existing_otp.code
        else:
            code = generate_code()
            DeviceVerification.objects.create(
                user=instance,
                device_fingerprint=device_hash,
                user_agent=user_agent,
                ip_address=ip,
                location=location,
                code=code
            )

        # Send OTP via Email
        if instance.email:
            send_verification_email(instance.email, code)

        # Send OTP via WhatsApp/SMS if phone number exists
        phone = getattr(instance.profile, 'phone_number', None)
        if phone:
            send_whatsapp_otp(phone, code)
            send_sms_otp(phone, code)

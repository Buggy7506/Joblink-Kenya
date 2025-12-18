from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.contrib.auth import get_user_model
from .models import Profile, TrustedDevice, DeviceVerification
from .utils import get_device_fingerprint, get_client_ip, generate_code, send_verification_email, send_whatsapp_otp, send_sms_otp

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
    Detects if the user logs in from a new device and triggers verification.
    """
    if created:
        # Skip new users (no need to verify their first device)
        return

    request = getattr(instance, "_request", None)
    if not request:
        # Request must be set in the view before saving user
        return

    device_hash = get_device_fingerprint(request)
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    # Check if device already exists
    device, created_device = TrustedDevice.objects.get_or_create(
        user=instance,
        device_fingerprint=device_hash,
        defaults={
            "user_agent": user_agent,
            "ip_address": ip,
        }
    )

    if created_device or not device.verified:
        # Generate OTP
        code = generate_code()
        # Save verification entry
        DeviceVerification.objects.create(
            user=instance,
            device_fingerprint=device_hash,
            user_agent=user_agent,
            ip_address=ip,
            code=code
        )
        # Send verification via email
        if instance.email:
            send_verification_email(instance.email, code)
        # Optional: send WhatsApp and SMS if phone number exists
        phone = getattr(instance.profile, 'phone_number', None)
        if phone:
            send_whatsapp_otp(phone, code)
            send_sms_otp(phone, code)

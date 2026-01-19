from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site

from .brevo_email import send_brevo_email

User = get_user_model()


def send_password_reset(user, request):
    """
    Generate a secure, branded password reset email using Brevo.
    """
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))

    # Pull domain from Site framework (safer & recommended)
    site = get_current_site(request)
    domain = site.domain
    protocol = "https" if request.is_secure() else "http"

    # Construct the reset URL
    reset_url = f"{protocol}://{domain}{reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})}"

    context = {
        "user": user,
        "email": user.email,
        "reset_url": reset_url,
        "domain": domain,
        "protocol": protocol,
        "site_name": "JobLink",
    }

    # Subject line comes from plain text template
    subject = render_to_string("password_reset_subject.txt", context).strip()

    # Beautiful HTML body
    html_content = render_to_string("password_reset_email.html", context)

    send_brevo_email(
        subject=subject,
        html_content=html_content,
        to_email=user.email,
        from_email="security@stepper.dpdns.org",
    )

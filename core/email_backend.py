from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model
from django.urls import reverse

from .brevo_email import send_brevo_email

User = get_user_model()

def send_password_reset(user, request):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))

    # Build proper Django reverse reset link
    reset_path = reverse("password_reset_confirm", kwargs={"uidb64": uid, "token": token})
    reset_url = request.build_absolute_uri(reset_path)

    context = {
        "user": user,
        "email": user.email,
        "reset_url": reset_url,
        "domain": request.get_host(),
        "protocol": "https" if request.is_secure() else "http",
        "site_name": "JobLink",
    }

    # Render the subject and HTML
    subject = render_to_string("password_reset_subject.txt", context).strip()
    html_content = render_to_string("password_reset_email.html", context)

    # Call your Brevo sender
    send_brevo_email(
        subject=subject,
        html_content=html_content,
        to_email=user.email,
        from_email="security@stepper.dpdns.org",
    )

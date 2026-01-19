from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model

from .brevo_email import send_brevo_email

User = get_user_model()

def send_password_reset(user, request):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    reset_url = request.build_absolute_uri(f"/reset/{uid}/{token}/")

    html = render_to_string("password_reset.html", {
        "user": user,
        "reset_url": reset_url,
    })

    send_brevo_email(
        subject="Reset Your Password",
        html_content=html,
        to_email=user.email,
    )

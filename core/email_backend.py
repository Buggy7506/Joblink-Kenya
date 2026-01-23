from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.utils.timezone import now

from .brevo_email import send_brevo_email

User = get_user_model()


def send_password_reset(user, request):
    """
    Generate a secure, Gmail-safe password reset email using Brevo shared sender.
    """

    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))

    site = get_current_site(request)
    domain = site.domain
    protocol = "https" if request.is_secure() else "http"

    reset_url = f"{protocol}://{domain}{reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})}"

    subject = "Password Reset Request – JobLink Kenya"

    current_year = now().year
    username = user.get_username()

    html_content = f"""
<!DOCTYPE html>
<html>
  <body style="margin:0; padding:0; font-family:Arial,Helvetica,sans-serif; background:#f7f7f7;">
    <table width="100%" cellpadding="0" cellspacing="0" style="padding:30px 0;">
      <tr>
        <td align="center">
          <table width="480" cellpadding="0" cellspacing="0"
                 style="background:#ffffff; border-radius:12px; padding:25px; box-shadow:0 4px 16px rgba(0,0,0,0.08);">

            <!-- LOGO -->
            <tr>
              <td align="center" style="padding-bottom:15px;">
                <img src="https://res.cloudinary.com/dc6z1giw2/image/upload/v1765303178/joblink-logo_xjj0qp.png"
                     alt="JobLink"
                     width="140"
                     style="display:block; margin:auto;">
              </td>
            </tr>

            <!-- TITLE -->
            <tr>
              <td style="text-align:center; font-size:22px; font-weight:bold; color:#00a8ff; padding-bottom:10px;">
                Password Reset Request
              </td>
            </tr>

            <!-- MESSAGE -->
            <tr>
              <td style="font-size:15px; line-height:1.6; color:#333;">
                Hi {username},<br><br>
                You’re receiving this email because someone requested a password reset
                for your JobLink account.<br><br>
                Click the secure button below to set a new password:
              </td>
            </tr>

            <!-- BUTTON -->
            <tr>
              <td align="center" style="padding:25px 0;">
                <a href="{reset_url}"
                   style="background:#00a8ff; color:white; text-decoration:none; font-weight:bold;
                          padding:12px 25px; border-radius:8px; display:inline-block;">
                  Reset Password
                </a>
              </td>
            </tr>

            <!-- EXPIRY -->
            <tr>
              <td style="font-size:13px; color:#999; padding-bottom:20px;">
                This link will expire soon. If you did not request this change, ignore this email.
              </td>
            </tr>

            <!-- FOOTER -->
            <tr>
              <td style="font-size:12px; color:#aaa; text-align:center; border-top:1px solid #eee; padding-top:15px;">
                © {current_year} JobLink • stepper.dpdns.org
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

    # ✅ NO from_email (Brevo shared sender safe)
    send_brevo_email(
        subject=subject,
        html_content=html_content,
        to_email=user.email,
    )

from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi, SendSmtpEmail
from django.conf import settings


def send_brevo_email(subject, html_content, to_email, text_content=""):
    """
    Sends an email using Brevo SHARED sender (best Gmail deliverability).
    """

    configuration = Configuration()
    configuration.api_key["api-key"] = settings.BREVO_API_KEY

    # ✅ FIX: ApiClient is NOT a context manager
    api_client = ApiClient(configuration)
    api_instance = TransactionalEmailsApi(api_client)

    email = SendSmtpEmail(
        # 🚫 DO NOT SET sender.email (Brevo shared sender)
        sender={
            "name": "Joblink Kenya"
        },
        to=[
            {"email": to_email}
        ],
        subject=subject,
        html_content=html_content,
        text_content=text_content or None,
        reply_to={
            "email": "support@stepper.dpdns.org",
            "name": "Joblink Kenya Support"
        }
    )

    api_instance.send_transac_email(email)

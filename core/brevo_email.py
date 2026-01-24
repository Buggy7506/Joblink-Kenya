from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi, SendSmtpEmail
from django.conf import settings
from sib_api_v3_sdk.rest import ApiException


def send_brevo_email(subject, html_content, to_email, text_content=""):
    """
    Sends an email using Brevo transactional API (shared sender compatible).
    """

    configuration = Configuration()
    configuration.api_key["api-key"] = settings.BREVO_API_KEY

    api_client = ApiClient(configuration)
    api_instance = TransactionalEmailsApi(api_client)

    email = SendSmtpEmail(
        sender={
            # ✅ REQUIRED by Brevo API
            "email": "support@stepper.dpdns.org",
            "name": "Joblink Kenya",
        },
        to=[
            {"email": to_email}
        ],
        subject=subject,
        html_content=html_content,
        text_content=text_content or None,
        reply_to={
            "email": "support@stepper.dpdns.org",
            "name": "Joblink Kenya Support",
        }
    )

    try:
        api_instance.send_transac_email(email)
    except ApiException as e:
        # Do NOT break password reset flow
        print("Brevo email error:", e)

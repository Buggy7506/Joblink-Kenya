from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi, SendSmtpEmail
from django.conf import settings

def send_brevo_email(subject, html_content, to_email, text_content=""):
    """
    Sends a fully rendered HTML email with an optional text fallback using Brevo.
    """
    configuration = Configuration()
    configuration.api_key['api-key'] = settings.BREVO_API_KEY

    with ApiClient(configuration) as api_client:
        api_instance = TransactionalEmailsApi(api_client)

        email = SendSmtpEmail(
            sender={"name": "Joblink Kenya", "email": "support@stepper.dpdns.org"},
            to=[{"email": to_email}],
            subject=subject,
            html_content=html_content,
            text_content=text_content or None,  # only attach if non-empty
        )

        api_instance.send_transac_email(email)

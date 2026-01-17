# tasks.py
from celery import shared_task
from .models import CompanyDocument, EmployerCompany
from django.contrib.auth import get_user_model
import os
from django.core.files import File
from django.conf import settings

User = get_user_model()

@shared_task(bind=True, autoretry_for=(Exception,), retry_kwargs={"max_retries": 5}, retry_backoff=True)
def save_employer_document(self, user_id, temp_file_path, doc_type):
    """
    Save a CompanyDocument asynchronously via Celery.
    Moves the temp file into Django's media storage and creates the CompanyDocument.
    Retries up to 5 times on failure.
    """
    try:
        user = User.objects.get(id=user_id)
        company = getattr(user, "employer_company", None)

        if not company:
            # Safety: create company if missing
            company = EmployerCompany.objects.create(user=user, company_name=user.username)

        # Open the temporary file and save it properly in MEDIA
        with open(temp_file_path, "rb") as f:
            django_file = File(f)
            doc = CompanyDocument.objects.create(
                company=company,
                document_type=doc_type,
            )
            doc.document.save(os.path.basename(temp_file_path), django_file)
            doc.save()

        # Remove temp file after saving
        os.remove(temp_file_path)

    except Exception as exc:
        # Retry automatically after 10 seconds if an error occurs
        raise self.retry(exc=exc, countdown=10)

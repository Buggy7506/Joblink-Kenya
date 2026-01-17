# tasks.py
from celery import shared_task
from .models import EmployerDocument

@shared_task(bind=True, autoretry_for=(Exception,), retry_kwargs={"max_retries": 5})
def save_employer_document(self, user_id, file_path, doc_type):
    EmployerDocument.objects.create(
        user_id=user_id,
        document=file_path,
        document_type=doc_type
    )

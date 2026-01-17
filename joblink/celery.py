import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "joblink.settings")

app = Celery("joblink")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

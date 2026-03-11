from __future__ import annotations

import hashlib
from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from core.aggregator.sources import NormalizedJob
from core.models import AggregatedJobRecord, Job


@dataclass
class IngestResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    invalid: int = 0


class JobAggregationService:
    def __init__(self, *, system_username: str = "aggregator-bot"):
        self.system_username = system_username

    def _get_or_create_system_employer(self):
        User = get_user_model()
        defaults = {
            "email": "aggregator-bot@joblink.local",
            "role": "employer",
            "first_name": "Job",
            "last_name": "Aggregator",
        }
        user, created = User.objects.get_or_create(username=self.system_username, defaults=defaults)
        updates = []
        if user.role != "employer":
            user.role = "employer"
            updates.append("role")
        if not user.email:
            user.email = defaults["email"]
            updates.append("email")
        if updates:
            user.save(update_fields=updates)
        return user

    @staticmethod
    def _fingerprint(item: NormalizedJob) -> str:
        raw = "|".join(
            [
                item.source.lower().strip(),
                item.source_job_id.lower().strip(),
                item.title.lower().strip(),
                item.company.lower().strip(),
                item.location.lower().strip(),
                item.apply_url.strip(),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def ingest(self, items: list[NormalizedJob]) -> IngestResult:
        result = IngestResult()
        employer = self._get_or_create_system_employer()

        for item in items:
            if not item.title or not item.apply_url:
                result.invalid += 1
                continue

            fingerprint = self._fingerprint(item)
            description = item.description or "No description available from source."

            source_job_id = item.source_job_id or fingerprint[:24]

            with transaction.atomic():
                record = AggregatedJobRecord.objects.select_related("job").filter(source=item.source, source_job_id=source_job_id).first()
                if not record:
                    record = AggregatedJobRecord.objects.select_related("job").filter(fingerprint=fingerprint).first()

                if record:
                    changed = False
                    job = record.job
                    if job.title != item.title:
                        job.title = item.title
                        changed = True
                    if job.description != description:
                        job.description = description
                        changed = True
                    if job.company != item.company:
                        job.company = item.company
                        changed = True
                    if job.location != item.location:
                        job.location = item.location
                        changed = True
                    if job.salary != item.salary:
                        job.salary = item.salary
                        changed = True
                    if not job.is_active:
                        job.is_active = True
                        changed = True

                    if changed:
                        job.save()
                        result.updated += 1
                    else:
                        result.unchanged += 1

                    record.source_job_id = source_job_id
                    record.fingerprint = fingerprint
                    record.apply_url = item.apply_url
                    record.source_url = item.source_url or item.apply_url
                    record.posted_date = item.posted_date
                    record.payload = item.metadata or {}
                    record.is_live = True
                    record.last_seen_at = timezone.now()
                    record.save(update_fields=[
                        "source_job_id",
                        "fingerprint",
                        "apply_url",
                        "source_url",
                        "posted_date",
                        "payload",
                        "is_live",
                        "last_seen_at",
                    ])
                    continue

                job = Job.objects.create(
                    title=item.title,
                    description=description,
                    location=item.location,
                    employer=employer,
                    company=item.company,
                    salary=item.salary,
                    is_active=True,
                )
                AggregatedJobRecord.objects.create(
                    job=job,
                    source=item.source,
                    source_job_id=source_job_id,
                    apply_url=item.apply_url,
                    source_url=item.source_url or item.apply_url,
                    fingerprint=fingerprint,
                    posted_date=item.posted_date,
                    payload=item.metadata or {},
                )
                result.created += 1

        return result

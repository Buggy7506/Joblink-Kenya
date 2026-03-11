from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from core.aggregator.sources import NormalizedJob
from core.models import AggregatedJobRecord, Job, JobCategory


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
        user, _created = User.objects.get_or_create(username=self.system_username, defaults=defaults)
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
    def _parse_salary_value(value) -> int | None:
        if value in (None, ""):
            return None
        if isinstance(value, (int, float)):
            parsed = int(value)
            return parsed if parsed > 0 else None
        if isinstance(value, str):
            numbers = [int(n) for n in re.findall(r"\d+", value.replace(",", ""))]
            if not numbers:
                return None
            parsed = max(numbers)
            return parsed if parsed > 0 else None
        return None

    def _extract_salary(self, item: NormalizedJob) -> int | None:
        if item.salary:
            return item.salary

        metadata = item.metadata or {}
        for key in ("salary", "salary_max", "salary_min", "compensation"):
            parsed = self._parse_salary_value(metadata.get(key))
            if parsed:
                return parsed

        if isinstance(item.description, str) and re.search(r"\b(kes|usd|eur|salary|compensation)\b", item.description, re.IGNORECASE):
            return self._parse_salary_value(item.description)

        return None

    @staticmethod
    def _extract_category_name(item: NormalizedJob) -> str:
        metadata = item.metadata or {}
        category = metadata.get("category") or metadata.get("job_type")
        if isinstance(category, str) and category.strip():
            return category.strip()

        tags = metadata.get("tags")
        if isinstance(tags, list) and tags:
            first = tags[0]
            if isinstance(first, str) and first.strip():
                return first.strip()

        return ""

    @staticmethod
    def _extract_logo_url(item: NormalizedJob) -> str:
        metadata = item.metadata or {}
        logo = item.company_logo_url or metadata.get("company_logo_url") or metadata.get("logo")
        return logo.strip() if isinstance(logo, str) else ""

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
            salary_value = self._extract_salary(item)
            category_name = self._extract_category_name(item)
            category_obj = None
            if category_name:
                category_obj, _ = JobCategory.objects.get_or_create(name=category_name[:100])
            payload = dict(item.metadata or {})
            logo_url = self._extract_logo_url(item)
            if logo_url:
                payload["company_logo_url"] = logo_url

            with transaction.atomic():
                record = AggregatedJobRecord.objects.select_related("job").filter(
                    source=item.source,
                    source_job_id=source_job_id,
                ).first()
                if not record:
                    record = AggregatedJobRecord.objects.select_related("job").filter(
                        fingerprint=fingerprint
                    ).first()

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
                    if job.salary != salary_value:
                        job.salary = salary_value
                        changed = True
                    if job.category_id != (category_obj.id if category_obj else None):
                        job.category = category_obj
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
                    record.payload = payload
                    record.is_live = True
                    record.last_seen_at = timezone.now()
                    record.save(
                        update_fields=[
                            "source_job_id",
                            "fingerprint",
                            "apply_url",
                            "source_url",
                            "posted_date",
                            "payload",
                            "is_live",
                            "last_seen_at",
                        ]
                    )
                    continue

                job = Job.objects.create(
                    title=item.title,
                    description=description,
                    location=item.location,
                    employer=employer,
                    company=item.company,
                    salary=salary_value,
                    category=category_obj,
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
                    payload=payload,
                    is_live=True,
                )
                result.created += 1

        return result

    def deactivate_stale_jobs(self, *, source: str, stale_hours: int = 48) -> int:
        threshold = timezone.now() - timedelta(hours=max(stale_hours, 1))
        stale_records = AggregatedJobRecord.objects.select_related("job").filter(
            source=source,
            is_live=True,
            last_seen_at__lt=threshold,
        )
        count = 0
        for record in stale_records:
            record.is_live = False
            record.save(update_fields=["is_live"])
            if record.job.is_active:
                record.job.is_active = False
                record.job.save(update_fields=["is_active"])
            count += 1
        return count

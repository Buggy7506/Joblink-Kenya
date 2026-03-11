from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import requests
from django.conf import settings


@dataclass
class NormalizedJob:
    title: str
    company: str
    location: str
    description: str
    apply_url: str
    source: str
    salary: int | None = None
    posted_date: datetime | None = None
    source_job_id: str = ""
    source_url: str = ""
    metadata: dict[str, Any] | None = None


class BaseSourceAdapter:
    source_name = "base"

    def fetch(self, *, limit: int = 100) -> list[NormalizedJob]:
        raise NotImplementedError


class RemotiveSourceAdapter(BaseSourceAdapter):
    """Lightweight adapter using Remotive public jobs API."""

    source_name = "remotive"
    endpoint = "https://remotive.com/api/remote-jobs"

    def fetch(self, *, limit: int = 100) -> list[NormalizedJob]:
        timeout = int(getattr(settings, "JOB_AGGREGATOR_HTTP_TIMEOUT", 25))
        response = requests.get(self.endpoint, timeout=timeout)
        response.raise_for_status()

        payload = response.json() or {}
        jobs = payload.get("jobs", [])[:limit]
        normalized: list[NormalizedJob] = []

        for raw in jobs:
            salary = None
            salary_text = (raw.get("salary") or "").strip()
            if salary_text:
                digits = "".join(ch for ch in salary_text if ch.isdigit())
                if digits:
                    try:
                        salary = int(digits[:8])
                    except ValueError:
                        salary = None

            posted_date = None
            publication = raw.get("publication_date")
            if publication:
                try:
                    posted_date = datetime.fromisoformat(publication.replace("Z", "+00:00"))
                except ValueError:
                    posted_date = None

            normalized.append(
                NormalizedJob(
                    title=(raw.get("title") or "Untitled role").strip(),
                    company=(raw.get("company_name") or "Unknown company").strip(),
                    location=(raw.get("candidate_required_location") or "Remote").strip(),
                    description=(raw.get("description") or "").strip(),
                    apply_url=(raw.get("url") or "").strip(),
                    source=self.source_name,
                    salary=salary,
                    posted_date=posted_date,
                    source_job_id=str(raw.get("id") or "").strip(),
                    source_url=(raw.get("url") or "").strip(),
                    metadata={
                        "job_type": raw.get("job_type"),
                        "category": raw.get("category"),
                        "tags": raw.get("tags") or [],
                    },
                )
            )

        return [job for job in normalized if job.apply_url]


def get_source_adapters() -> list[BaseSourceAdapter]:
    return [RemotiveSourceAdapter()]

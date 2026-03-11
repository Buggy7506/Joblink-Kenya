from __future__ import annotations

from dataclasses import dataclass
import logging
from datetime import datetime
from typing import Any

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


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


class ArbeitnowSourceAdapter(BaseSourceAdapter):
    source_name = "arbeitnow"
    endpoint = "https://www.arbeitnow.com/api/job-board-api"

    def fetch(self, *, limit: int = 100) -> list[NormalizedJob]:
        timeout = int(getattr(settings, "JOB_AGGREGATOR_HTTP_TIMEOUT", 25))
        normalized: list[NormalizedJob] = []
        page = 1

        while len(normalized) < limit:
            response = requests.get(self.endpoint, params={"page": page}, timeout=timeout)
            response.raise_for_status()
            payload = response.json() or {}
            jobs = payload.get("data", [])
            if not jobs:
                break

            for raw in jobs:
                normalized.append(
                    NormalizedJob(
                        title=(raw.get("title") or "Untitled role").strip(),
                        company=(raw.get("company_name") or "Unknown company").strip(),
                        location=((raw.get("location") or "Remote") if isinstance(raw.get("location"), str) else "Remote").strip(),
                        description=(raw.get("description") or "").strip(),
                        apply_url=(raw.get("url") or "").strip(),
                        source=self.source_name,
                        source_job_id=str(raw.get("slug") or raw.get("id") or "").strip(),
                        source_url=(raw.get("url") or "").strip(),
                        metadata={
                            "remote": raw.get("remote"),
                            "tags": raw.get("tags") or [],
                        },
                    )
                )
                if len(normalized) >= limit:
                    break
            page += 1

        return [job for job in normalized if job.apply_url]


ADAPTER_REGISTRY: dict[str, type[BaseSourceAdapter]] = {
    RemotiveSourceAdapter.source_name: RemotiveSourceAdapter,
    ArbeitnowSourceAdapter.source_name: ArbeitnowSourceAdapter,
}


def get_source_adapters() -> list[BaseSourceAdapter]:
    configured = getattr(settings, "JOB_AGGREGATOR_ENABLED_SOURCES", tuple(ADAPTER_REGISTRY.keys()))
    adapters: list[BaseSourceAdapter] = []

    for source_name in configured:
        adapter_cls = ADAPTER_REGISTRY.get(source_name)
        if adapter_cls:
            adapters.append(adapter_cls())
            continue

        logger.warning("Unknown job aggregator source configured: %s", source_name)

    return adapters

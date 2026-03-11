from __future__ import annotations

from dataclasses import dataclass
import logging
from datetime import datetime
from typing import Any
from xml.etree import ElementTree

import requests
from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

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

    @staticmethod
    def _timeout() -> int:
        return int(getattr(settings, "JOB_AGGREGATOR_HTTP_TIMEOUT", 25))


class RemotiveSourceAdapter(BaseSourceAdapter):
    source_name = "remotive"
    endpoint = "https://remotive.com/api/remote-jobs"

    def fetch(self, *, limit: int = 100) -> list[NormalizedJob]:
        response = requests.get(self.endpoint, timeout=self._timeout())
        response.raise_for_status()

        payload = response.json() or {}
        jobs = payload.get("jobs", [])[:limit]
        normalized: list[NormalizedJob] = []

        for raw in jobs:
            posted_date = None
            publication = raw.get("publication_date")
            if publication:
                posted_date = parse_datetime(publication.replace("Z", "+00:00"))

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
        normalized: list[NormalizedJob] = []
        page = 1

        while len(normalized) < limit:
            response = requests.get(self.endpoint, params={"page": page}, timeout=self._timeout())
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
                        metadata={"remote": raw.get("remote"), "tags": raw.get("tags") or []},
                    )
                )
                if len(normalized) >= limit:
                    break
            page += 1

        return [job for job in normalized if job.apply_url]


class RemoteOkSourceAdapter(BaseSourceAdapter):
    source_name = "remoteok"
    endpoint = "https://remoteok.com/api"

    def fetch(self, *, limit: int = 100) -> list[NormalizedJob]:
        response = requests.get(self.endpoint, timeout=self._timeout(), headers={"User-Agent": "JoblinkKenyaBot/1.0"})
        response.raise_for_status()
        payload = response.json() or []
        if not isinstance(payload, list):
            return []

        normalized: list[NormalizedJob] = []
        for raw in payload:
            if not isinstance(raw, dict) or raw.get("id") is None:
                continue
            url = raw.get("url") or raw.get("apply_url") or ""
            if url and url.startswith("/"):
                url = f"https://remoteok.com{url}"

            normalized.append(
                NormalizedJob(
                    title=(raw.get("position") or "Untitled role").strip(),
                    company=(raw.get("company") or "Unknown company").strip(),
                    location=(raw.get("location") or "Remote").strip(),
                    description=(raw.get("description") or "").strip(),
                    apply_url=url.strip(),
                    source=self.source_name,
                    source_job_id=str(raw.get("id") or "").strip(),
                    source_url=url.strip(),
                    metadata={"tags": raw.get("tags") or []},
                )
            )
            if len(normalized) >= limit:
                break

        return [job for job in normalized if job.apply_url]


class GenericRSSSourceAdapter(BaseSourceAdapter):
    source_name = "rss"
    feed_url = ""

    def fetch(self, *, limit: int = 100) -> list[NormalizedJob]:
        if not self.feed_url:
            return []
        response = requests.get(self.feed_url, timeout=self._timeout())
        response.raise_for_status()

        root = ElementTree.fromstring(response.content)
        normalized: list[NormalizedJob] = []

        for item in root.findall(".//item"):
            title = (item.findtext("title") or "Untitled role").strip()
            link = (item.findtext("link") or "").strip()
            description = (item.findtext("description") or "").strip()
            pub_date_raw = (item.findtext("pubDate") or "").strip()
            posted_date = parse_datetime(pub_date_raw) if pub_date_raw else None

            normalized.append(
                NormalizedJob(
                    title=title,
                    company="Unknown company",
                    location="Remote",
                    description=description,
                    apply_url=link,
                    source=self.source_name,
                    source_job_id=link,
                    source_url=link,
                    posted_date=posted_date,
                )
            )
            if len(normalized) >= limit:
                break

        return [job for job in normalized if job.apply_url]


class ConfigurableJSONSourceAdapter(BaseSourceAdapter):
    """
    Generic JSON adapter for sources without a stable universal public API contract.
    Configure endpoint + json key + field mapping via env/settings and reuse this adapter.
    """

    source_name = "json-config"

    def __init__(self, *, source_name: str, endpoint_setting: str, list_key_setting: str = ""):
        self.source_name = source_name
        self.endpoint_setting = endpoint_setting
        self.list_key_setting = list_key_setting

    def fetch(self, *, limit: int = 100) -> list[NormalizedJob]:
        endpoint = getattr(settings, self.endpoint_setting, "") or ""
        if not endpoint:
            logger.info("Skipping %s source: %s not configured", self.source_name, self.endpoint_setting)
            return []

        response = requests.get(endpoint, timeout=self._timeout())
        response.raise_for_status()
        payload = response.json() or {}

        jobs = payload
        list_key = getattr(settings, self.list_key_setting, "") if self.list_key_setting else ""
        if list_key and isinstance(payload, dict):
            jobs = payload.get(list_key, [])
        if isinstance(jobs, dict):
            jobs = jobs.get("jobs", [])
        if not isinstance(jobs, list):
            return []

        normalized: list[NormalizedJob] = []
        for raw in jobs[:limit]:
            if not isinstance(raw, dict):
                continue
            apply_url = (raw.get("apply_url") or raw.get("url") or raw.get("link") or "").strip()
            normalized.append(
                NormalizedJob(
                    title=(raw.get("title") or raw.get("position") or "Untitled role").strip(),
                    company=(raw.get("company") or raw.get("company_name") or "Unknown company").strip(),
                    location=(raw.get("location") or "Remote").strip(),
                    description=(raw.get("description") or "").strip(),
                    apply_url=apply_url,
                    source=self.source_name,
                    source_job_id=str(raw.get("id") or raw.get("slug") or apply_url).strip(),
                    source_url=apply_url,
                    metadata={"raw": raw},
                    posted_date=timezone.now(),
                )
            )

        return [job for job in normalized if job.apply_url]


def _rss_adapter(name: str, url: str):
    class _Adapter(GenericRSSSourceAdapter):
        source_name = name
        feed_url = url

    return _Adapter


ADAPTER_REGISTRY: dict[str, type[BaseSourceAdapter]] = {
    "remotive": RemotiveSourceAdapter,
    "arbeitnow": ArbeitnowSourceAdapter,
    "remoteok": RemoteOkSourceAdapter,
    "weworkremotely": _rss_adapter("weworkremotely", "https://weworkremotely.com/remote-jobs.rss"),
    "jobicy": _rss_adapter("jobicy", "https://jobicy.com/?feed=job_feed"),
    # Aliases requested
    "remotive_api": RemotiveSourceAdapter,
    "remotive_global": RemotiveSourceAdapter,
}

CONFIGURABLE_JSON_SOURCES: dict[str, tuple[str, str]] = {
    "adzuna": ("JOB_AGGREGATOR_ADZUNA_ENDPOINT", "JOB_AGGREGATOR_ADZUNA_LIST_KEY"),
    "jooble": ("JOB_AGGREGATOR_JOOBLE_ENDPOINT", "JOB_AGGREGATOR_JOOBLE_LIST_KEY"),
    "greenhouse": ("JOB_AGGREGATOR_GREENHOUSE_ENDPOINT", "JOB_AGGREGATOR_GREENHOUSE_LIST_KEY"),
    "lever": ("JOB_AGGREGATOR_LEVER_ENDPOINT", "JOB_AGGREGATOR_LEVER_LIST_KEY"),
    "ashby": ("JOB_AGGREGATOR_ASHBY_ENDPOINT", "JOB_AGGREGATOR_ASHBY_LIST_KEY"),
    "smartrecruiters": ("JOB_AGGREGATOR_SMARTRECRUITERS_ENDPOINT", "JOB_AGGREGATOR_SMARTRECRUITERS_LIST_KEY"),
    "workable": ("JOB_AGGREGATOR_WORKABLE_ENDPOINT", "JOB_AGGREGATOR_WORKABLE_LIST_KEY"),
    "bamboohr": ("JOB_AGGREGATOR_BAMBOOHR_ENDPOINT", "JOB_AGGREGATOR_BAMBOOHR_LIST_KEY"),
    "personio": ("JOB_AGGREGATOR_PERSONIO_ENDPOINT", "JOB_AGGREGATOR_PERSONIO_LIST_KEY"),
    "recruitee": ("JOB_AGGREGATOR_RECRUITEE_ENDPOINT", "JOB_AGGREGATOR_RECRUITEE_LIST_KEY"),
    "remotewx": ("JOB_AGGREGATOR_REMOTEWX_ENDPOINT", "JOB_AGGREGATOR_REMOTEWX_LIST_KEY"),
    "ycombinator": ("JOB_AGGREGATOR_YCOMBINATOR_ENDPOINT", "JOB_AGGREGATOR_YCOMBINATOR_LIST_KEY"),
    "wellfound": ("JOB_AGGREGATOR_WELLFOUND_ENDPOINT", "JOB_AGGREGATOR_WELLFOUND_LIST_KEY"),
    "usajobs": ("JOB_AGGREGATOR_USAJOBS_ENDPOINT", "JOB_AGGREGATOR_USAJOBS_LIST_KEY"),
}


def _build_adapter(name: str) -> BaseSourceAdapter | None:
    adapter_cls = ADAPTER_REGISTRY.get(name)
    if adapter_cls:
        return adapter_cls()

    json_cfg = CONFIGURABLE_JSON_SOURCES.get(name)
    if json_cfg:
        endpoint_setting, list_key_setting = json_cfg
        return ConfigurableJSONSourceAdapter(
            source_name=name,
            endpoint_setting=endpoint_setting,
            list_key_setting=list_key_setting,
        )

    return None


def get_source_adapters() -> list[BaseSourceAdapter]:
    configured = getattr(settings, "JOB_AGGREGATOR_ENABLED_SOURCES", tuple(ADAPTER_REGISTRY.keys()))
    adapters: list[BaseSourceAdapter] = []

    for source_name in configured:
        adapter = _build_adapter(source_name)
        if adapter:
            adapters.append(adapter)
            continue

        logger.warning("Unknown job aggregator source configured: %s", source_name)

    return adapters

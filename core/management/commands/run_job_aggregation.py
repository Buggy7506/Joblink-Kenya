from django.conf import settings
from django.core.management.base import BaseCommand

from core.aggregator.service import JobAggregationService
from core.aggregator.sources import get_source_adapters


class Command(BaseCommand):
    help = "Fetch and ingest jobs from configured external aggregation sources."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100, help="Max jobs per source")
        parser.add_argument(
            "--stale-hours",
            type=int,
            default=int(getattr(settings, "JOB_AGGREGATOR_STALE_HOURS", 48)),
            help="Mark aggregated jobs inactive if not seen for this many hours",
        )

    def handle(self, *args, **options):
        limit = max(1, options["limit"])
        stale_hours = max(1, options["stale_hours"])
        service = JobAggregationService()

        total_created = 0
        total_updated = 0
        total_unchanged = 0
        total_invalid = 0
        total_deactivated = 0

        for adapter in get_source_adapters():
            self.stdout.write(self.style.NOTICE(f"Fetching source: {adapter.source_name}"))
            try:
                jobs = adapter.fetch(limit=limit)
            except Exception as exc:
                self.stderr.write(self.style.ERROR(f"Source {adapter.source_name} failed: {exc}"))
                continue

            result = service.ingest(jobs)
            deactivated = service.deactivate_stale_jobs(source=adapter.source_name, stale_hours=stale_hours)
            total_created += result.created
            total_updated += result.updated
            total_unchanged += result.unchanged
            total_invalid += result.invalid
            total_deactivated += deactivated

            self.stdout.write(
                self.style.SUCCESS(
                    f"{adapter.source_name}: created={result.created}, updated={result.updated}, "
                    f"unchanged={result.unchanged}, invalid={result.invalid}, deactivated={deactivated}"
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                "Aggregation complete: "
                f"created={total_created}, updated={total_updated}, unchanged={total_unchanged}, "
                f"invalid={total_invalid}, deactivated={total_deactivated}"
            )
        )

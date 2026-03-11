from django.core.management.base import BaseCommand

from core.aggregator.service import JobAggregationService
from core.aggregator.sources import get_source_adapters


class Command(BaseCommand):
    help = "Fetch and ingest jobs from configured external aggregation sources."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100, help="Max jobs per source")

    def handle(self, *args, **options):
        limit = max(1, options["limit"])
        service = JobAggregationService()

        total_created = 0
        total_updated = 0
        total_unchanged = 0
        total_invalid = 0

        for adapter in get_source_adapters():
            self.stdout.write(self.style.NOTICE(f"Fetching source: {adapter.source_name}"))
            try:
                jobs = adapter.fetch(limit=limit)
            except Exception as exc:
                self.stderr.write(self.style.ERROR(f"Source {adapter.source_name} failed: {exc}"))
                continue

            result = service.ingest(jobs)
            total_created += result.created
            total_updated += result.updated
            total_unchanged += result.unchanged
            total_invalid += result.invalid
            self.stdout.write(
                self.style.SUCCESS(
                    f"{adapter.source_name}: created={result.created}, updated={result.updated}, "
                    f"unchanged={result.unchanged}, invalid={result.invalid}"
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                "Aggregation complete: "
                f"created={total_created}, updated={total_updated}, unchanged={total_unchanged}, invalid={total_invalid}"
            )
        )

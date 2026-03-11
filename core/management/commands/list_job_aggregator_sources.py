from django.conf import settings
from django.core.management.base import BaseCommand

from core.aggregator.sources import ADAPTER_REGISTRY, CONFIGURABLE_JSON_SOURCES


class Command(BaseCommand):
    help = "List available and enabled job aggregator sources."

    def handle(self, *args, **options):
        enabled = set(getattr(settings, "JOB_AGGREGATOR_ENABLED_SOURCES", ()))
        self.stdout.write(self.style.NOTICE("Available sources:"))
        known = set(ADAPTER_REGISTRY.keys()) | set(CONFIGURABLE_JSON_SOURCES.keys())
        for name in sorted(known):
            marker = "enabled" if name in enabled else "disabled"
            self.stdout.write(f" - {name} ({marker})")

        unknown = sorted(enabled - known)
        if unknown:
            self.stdout.write(self.style.WARNING("Unknown configured sources:"))
            for name in unknown:
                self.stdout.write(f" - {name}")

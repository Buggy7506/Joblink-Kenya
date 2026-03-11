from django.conf import settings
from django.core.management.base import BaseCommand

from core.aggregator.sources import ADAPTER_REGISTRY


class Command(BaseCommand):
    help = "List available and enabled job aggregator sources."

    def handle(self, *args, **options):
        enabled = set(getattr(settings, "JOB_AGGREGATOR_ENABLED_SOURCES", ()))
        self.stdout.write(self.style.NOTICE("Available sources:"))
        for name in sorted(ADAPTER_REGISTRY.keys()):
            marker = "enabled" if name in enabled else "disabled"
            self.stdout.write(f" - {name} ({marker})")

        unknown = sorted(enabled - set(ADAPTER_REGISTRY.keys()))
        if unknown:
            self.stdout.write(self.style.WARNING("Unknown configured sources:"))
            for name in unknown:
                self.stdout.write(f" - {name}")

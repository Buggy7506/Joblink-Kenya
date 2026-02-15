from __future__ import annotations


class SuppressProbeNoiseFilter:
    """Suppress repetitive internet-probe warnings that do not need alerting."""

    suppressed_message_tokens = (
        "Not Found: /.env",
        "Not Found: /.env.local",
        "Not Found: /.env.production",
        "Not Found: /.env.backup",
        "Not Found: /.git/HEAD",
        "Not Found: /php_info.php",
        "Not Found: /graphql",
        "Not Found: /server-status",
        "Not Found: /server-info",
        "Not Found: /api/v1/namespaces/default/secrets",
        "Forbidden (Referer checking failed - no Referer.): /",
    )

    def __init__(self, *args, **kwargs):
        pass

    def filter(self, record) -> bool:
        message = record.getMessage()
        return not any(token in message for token in self.suppressed_message_tokens)


class SuppressAsyncCancelNoiseFilter:
    """Suppress noisy disconnect cancellations emitted by the ASGI sync adapter."""

    suppressed_message_tokens = (
        "CancelledError exception in shielded future",
    )

    def __init__(self, *args, **kwargs):
        pass

    def filter(self, record) -> bool:
        message = record.getMessage()
        return not any(token in message for token in self.suppressed_message_tokens)

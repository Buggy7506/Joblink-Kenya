"""
ASGI config for joblink project.

Exposes the ASGI callable as a module-level variable named `application`.
"""

import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

# --------------------------------------------------
# Set Django settings module BEFORE importing Channels
# --------------------------------------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "joblink.settings")

# --------------------------------------------------
# Initialize Django ASGI application early
# --------------------------------------------------
django_asgi_app = get_asgi_application()

# --------------------------------------------------
# Import websocket routing AFTER Django setup
# --------------------------------------------------
import core.routing  # noqa: E402

# --------------------------------------------------
# ASGI application
# --------------------------------------------------
application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(core.routing.websocket_urlpatterns)
    ),
})

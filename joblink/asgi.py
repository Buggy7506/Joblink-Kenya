"""
ASGI config for joblink project.

It exposes the ASGI callable as a module-level variable named `application`.
"""

import os
from django.core.asgi import get_asgi_application

# -----------------------------
# Set Django settings module
# -----------------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "joblink.settings")

# -----------------------------
# Reference to Django ASGI app for HTTP requests
# -----------------------------
django_asgi_app = get_asgi_application()

# -----------------------------
# Channels imports (after settings are configured)
# -----------------------------
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import core.routing  # WebSocket routes

# -----------------------------
# ASGI application with HTTP & WebSocket support
# -----------------------------
application = ProtocolTypeRouter({
    "http": django_asgi_app,  # Handle standard HTTP requests
    "websocket": AuthMiddlewareStack(
        URLRouter(core.routing.websocket_urlpatterns)  # Handle WebSocket connections
    ),
})

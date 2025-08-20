"""
ASGI config for joblink project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os
import django  # 🔹 Import django

# 🔹 Set the settings module and initialize Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'joblink.settings')
django.setup()


from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import core.routing
from django.core.asgi import get_asgi_application
django_asgi_app = get_asgi_application()  # Keep reference to HTTP app

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(core.routing.websocket_urlpatterns)
    ),
})

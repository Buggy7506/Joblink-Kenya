from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path("ws/chat/<int:application_id>/", consumers.ChatConsumer.as_asgi(), name="ws_chat"),
]

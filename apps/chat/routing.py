"""
WebSocket URL patterns for the entire application.

All WebSocket consumers are registered here — this is the single file
that asgi.py imports. Do not create separate routing.py files in other apps.
"""

from django.urls import re_path

from apps.chat.consumers import ChatConsumer
from apps.notifications.consumers import NotificationConsumer

websocket_urlpatterns = [
    re_path(r"ws/chat/(?P<conversation_id>[^/]+)/$", ChatConsumer.as_asgi()),
    re_path(r"ws/notifications/$", NotificationConsumer.as_asgi()),
]

from django.urls import re_path

# Consumers will be imported here once the chat feature is implemented.
# Example:
# from apps.chat import consumers

# WebSocket URL patterns for the chat application.
# These are registered in asgi.py via ProtocolTypeRouter.
websocket_urlpatterns = [
    # re_path(r'ws/chat/(?P<room_id>[^/]+)/$', consumers.ChatConsumer.as_asgi()),
    # re_path(r'ws/notifications/$', consumers.NotificationConsumer.as_asgi()),
]

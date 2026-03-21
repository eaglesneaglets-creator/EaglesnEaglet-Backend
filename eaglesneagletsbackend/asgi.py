"""
ASGI config for eaglesneagletsbackend project.

Handles both HTTP (via Django's ASGI app) and WebSocket (via Django Channels)
connections through a single Daphne server process.
"""

import os
import django
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eaglesneagletsbackend.settings.local')

# Django must be fully initialized before importing anything that touches
# models, settings, or apps (including channels routing modules).
django.setup()

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator

from apps.chat.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    # Django's standard HTTP request handling
    "http": get_asgi_application(),
    # WebSocket connections — validated against ALLOWED_HOSTS, then JWT-authenticated
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(websocket_urlpatterns)
        )
    ),
})

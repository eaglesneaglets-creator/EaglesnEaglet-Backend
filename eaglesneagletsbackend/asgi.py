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

from urllib.parse import urlparse

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.conf import settings

from apps.chat.routing import websocket_urlpatterns


class CorsOriginValidator:
    """
    WebSocket origin validator that mirrors the HTTP CORS policy.

    AllowedHostsOriginValidator checks the Origin header against ALLOWED_HOSTS
    (the backend domain). This breaks cross-origin WebSocket connections from
    the frontend because the frontend domain is not in ALLOWED_HOSTS — Chrome
    always sends a strict Origin header and gets rejected before auth runs.

    This validator checks against CORS_ALLOWED_ORIGINS instead, which already
    contains the trusted frontend domain(s). Connections with no Origin header
    (e.g. native apps, curl) are allowed through.
    """

    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            headers = dict(scope.get("headers", []))
            origin = headers.get(b"origin", b"").decode("ascii")

            if origin:
                allowed = getattr(settings, "CORS_ALLOWED_ORIGINS", [])
                if origin not in allowed:
                    await send({"type": "websocket.close", "code": 403})
                    return

        await self.application(scope, receive, send)


application = ProtocolTypeRouter({
    # Django's standard HTTP request handling
    "http": get_asgi_application(),
    # WebSocket connections — validated against CORS_ALLOWED_ORIGINS, then JWT-authenticated
    "websocket": CorsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(websocket_urlpatterns)
        )
    ),
})

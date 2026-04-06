"""
Notification WebSocket Consumer

Authenticates via the httpOnly `access_token` cookie sent automatically
by the browser on the WebSocket Upgrade handshake. Joins the user's
personal notification channel group. Messages are pushed by
NotificationService.push_to_websocket (wired in MM-18).
"""

import logging

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

logger = logging.getLogger(__name__)


class NotificationConsumer(AsyncJsonWebsocketConsumer):
    """Real-time notification delivery over WebSocket."""

    async def connect(self):
        token = self._get_token_from_cookie()
        if not token:
            logger.warning("NotificationConsumer: no access_token cookie in WebSocket upgrade")
        user = await self._authenticate(token)
        if user is None:
            logger.warning("NotificationConsumer: auth failed (token=%s)", "present" if token else "missing")
            await self.close(code=4001)
            return

        self.user = user
        self.group_name = f"notifications_{user.id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.info("NotificationConsumer connected: user=%s", user.id)

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def notification_message(self, event):
        """Handler for messages sent via channel_layer.group_send."""
        await self.send_json(event["data"])

    # ── Private helpers ────────────────────────────────────────────────────

    def _get_token_from_cookie(self) -> str | None:
        """Read JWT from the query string (?token=) or the httpOnly access_token cookie.

        Cross-origin WebSocket upgrades (frontend and backend on different Railway
        subdomains, which are in the Public Suffix List) cause Chrome to block
        cookies even with SameSite=None. The store token in the query string is
        the reliable fallback. Cookie is tried first for same-origin clients.
        """
        # 1. Query string — reliable for cross-origin (Chrome PSL behaviour)
        from urllib.parse import parse_qs
        qs = parse_qs(self.scope.get("query_string", b"").decode())
        if token := qs.get("token", [None])[0]:
            return token
        # 2. httpOnly cookie — fallback for same-origin clients
        cookies = self.scope.get("cookies", {})
        return cookies.get("access_token")

    async def _authenticate(self, token_str: str | None):
        if not token_str:
            return None
        try:
            token = AccessToken(token_str)
            user_id = token["user_id"]
            from channels.db import database_sync_to_async
            from apps.users.models import User
            return await database_sync_to_async(User.objects.get)(id=user_id)
        except (InvalidToken, TokenError):
            return None
        except Exception:
            logger.exception("Unexpected error during NotificationConsumer authentication")
            return None

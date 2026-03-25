"""
Notification WebSocket Consumer

Authenticates via JWT ?token= query param, then joins the user's
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
        token = self._get_token_from_query()
        user = await self._authenticate(token)
        if user is None:
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

    def _get_token_from_query(self) -> str | None:
        from urllib.parse import parse_qs
        query_string = self.scope.get("query_string", b"").decode()
        params = parse_qs(query_string)
        tokens = params.get("token", [])
        return tokens[0] if tokens else None

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

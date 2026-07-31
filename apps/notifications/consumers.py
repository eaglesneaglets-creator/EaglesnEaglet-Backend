"""
Notification WebSocket Consumer

Authenticates via the httpOnly `access_token` cookie sent automatically
by the browser on the WebSocket Upgrade handshake. Joins the user's
personal notification channel group. Messages are pushed by
NotificationService.push_to_websocket (wired in MM-18).
"""

import logging

from channels.generic.websocket import AsyncJsonWebsocketConsumer

from core.ws_auth import WS_UNAUTHENTICATED, authenticate_ws

logger = logging.getLogger(__name__)


class NotificationConsumer(AsyncJsonWebsocketConsumer):
    """Real-time notification delivery over WebSocket."""

    async def connect(self):
        # Shared helper: validates the token AND re-reads account state, so a
        # suspended/deactivated user's still-valid token cannot hold a socket.
        user = await authenticate_ws(self.scope)
        if user is None:
            logger.warning("NotificationConsumer: WebSocket authentication rejected")
            await self.close(code=WS_UNAUTHENTICATED)
            return

        self.user = user
        self.group_name = f"notifications_{user.id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.info("NotificationConsumer connected: user=%s", user.id)

    async def disconnect(self, _close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def notification_message(self, event):
        """Handler for messages sent via channel_layer.group_send."""
        await self.send_json(event["data"])

    # Token reading + user resolution live in core.ws_auth so this consumer and
    # ChatConsumer cannot drift apart on account-state checks.

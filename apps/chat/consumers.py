"""
Chat WebSocket Consumer

URL: ws/chat/{conversation_id}/

Authentication: JWT read from the httpOnly `access_token` cookie sent
automatically by the browser on the WebSocket Upgrade handshake.

Messages in:
  {"type": "chat.message", "content": "..."}
  {"type": "chat.read"}

Messages out (broadcast to group):
  {"type": "chat.message", "id": "...", "conversation": "...",
   "sender_id": "...", "sender_name": "...", "content": "...", "created_at": "..."}
"""

import logging

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from core.ws_auth import WS_UNAUTHENTICATED, authenticate_ws
from core.ws_throttle import (
    CHAT_MESSAGE_BUCKET,
    CHAT_READ_BUCKET,
    RateLimitExceeded,
    TokenBucket,
)

logger = logging.getLogger(__name__)


class ChatConsumer(AsyncJsonWebsocketConsumer):

    async def connect(self):
        self.conversation_id = self.scope["url_route"]["kwargs"]["conversation_id"]
        self.group_name = f"chat_{self.conversation_id}"

        # Shared helper: validates the token AND re-reads account state, so a
        # suspended/deactivated user's still-valid token cannot hold a socket.
        user = await authenticate_ws(self.scope)
        if user is None:
            await self.close(code=WS_UNAUTHENTICATED)
            return

        # Verify the user is a participant in this conversation
        is_participant = await self._is_participant(user, self.conversation_id)
        if not is_participant:
            await self.close(code=4003)
            return

        # Gate eaglet WS connections behind active program enrollment (plan 14-03).
        if not await self._has_active_program(user):
            await self.close(code=4004)
            return

        self.user = user
        # Per-connection throttles. Frames bypass DRF's throttling entirely, so
        # without these one socket could persist messages as fast as the network
        # allowed (measured: 50 in 0.44s) and fan each one out to the group.
        self._send_bucket = TokenBucket(**CHAT_MESSAGE_BUCKET)
        self._read_bucket = TokenBucket(**CHAT_READ_BUCKET)
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.info(
            "ChatConsumer connected: user=%s conv=%s",
            user.id, self.conversation_id,
        )

    async def disconnect(self, _close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        msg_type = content.get("type")

        # Throttle at the dispatch point so every frame type is covered and no
        # handler can be added later that forgets to check.
        bucket = {
            "chat.message": getattr(self, "_send_bucket", None),
            "chat.read": getattr(self, "_read_bucket", None),
        }.get(msg_type)
        if bucket is not None:
            try:
                bucket.consume()
            except RateLimitExceeded as exc:
                # Report rather than disconnect: a legitimate fast typer should
                # be slowed, not dropped mid-conversation.
                await self.send_json({
                    "type": "error",
                    "code": "rate_limited",
                    "message": "You're sending messages too quickly. Please slow down.",
                    "retry_after": round(exc.retry_after, 1),
                })
                return

        if msg_type == "chat.message":
            await self._handle_send_message(content.get("content", ""))
        elif msg_type == "chat.read":
            await self._handle_mark_read()
        else:
            await self.send_json({"type": "error", "message": "Unknown message type."})

    async def chat_message(self, event):
        """Handler invoked by channel_layer.group_send — broadcasts to WS client."""
        await self.send_json(event["data"])

    # ── Handlers ───────────────────────────────────────────────────────────

    async def _handle_send_message(self, raw_content: str):
        # SECURITY: Enforce message length limit to prevent DoS via DB bloat.
        if not raw_content or not raw_content.strip():
            await self.send_json({"type": "error", "message": "Message cannot be empty."})
            return
        if len(raw_content) > 4000:
            await self.send_json({"type": "error", "message": "Message exceeds maximum length of 4000 characters."})
            return

        from apps.chat.models import Conversation
        try:
            conversation = await database_sync_to_async(
                Conversation.objects.get
            )(id=self.conversation_id)
        except Conversation.DoesNotExist:
            await self.send_json({"type": "error", "message": "Conversation not found."})
            return

        # SECURITY: Re-validate participant membership on every message send.
        # A user may have been removed from the conversation after connecting.
        still_participant = await self._is_participant(self.user, self.conversation_id)
        if not still_participant:
            await self.close(code=4003)
            return

        from apps.chat.services import ChatService
        try:
            msg = await database_sync_to_async(ChatService.create_message)(
                conversation, self.user, raw_content
            )
        except Exception as exc:
            await self.send_json({"type": "error", "message": str(exc)})
            return

        payload = {
            "type": "chat.message",
            "id": str(msg.id),
            "conversation": str(msg.conversation_id),
            "sender_id": str(self.user.id),
            "sender_name": f"{self.user.first_name} {self.user.last_name}".strip(),
            "content": msg.content,
            "created_at": msg.created_at.isoformat(),
        }
        await self.channel_layer.group_send(
            self.group_name, {"type": "chat_message", "data": payload}
        )

    async def _handle_mark_read(self):
        from apps.chat.models import Conversation
        from apps.chat.services import ChatService
        try:
            conversation = await database_sync_to_async(
                Conversation.objects.get
            )(id=self.conversation_id)
            await database_sync_to_async(ChatService.mark_conversation_read)(
                conversation, self.user
            )
        except Exception:
            pass  # Read receipt failure is non-critical

    # ── Auth helpers ────────────────────────────────────────────────────────

    # Token reading + user resolution live in core.ws_auth so this consumer and
    # NotificationConsumer cannot drift apart on account-state checks.

    async def _has_active_program(self, user) -> bool:
        """Eagles + admins bypass; eaglets need an ACTIVE ProgramEnrollment."""
        if user.is_staff or getattr(user, "role", None) != "eaglet":
            return True
        from apps.nests.models_program import ProgramEnrollment
        return await database_sync_to_async(
            ProgramEnrollment.objects.filter(
                mentee=user, status=ProgramEnrollment.Status.ACTIVE,
            ).exists
        )()

    async def _is_participant(self, user, conversation_id: str) -> bool:
        from apps.chat.models import Conversation
        try:
            conv = await database_sync_to_async(
                Conversation.objects.get
            )(id=conversation_id)
            return await database_sync_to_async(
                conv.participants.filter(id=user.id).exists
            )()
        except Exception:
            return False

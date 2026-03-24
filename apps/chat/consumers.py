"""
Chat WebSocket Consumer

URL: ws/chat/{conversation_id}/?token=<jwt>

Authentication: JWT extracted from query string (browsers cannot set
custom headers on WebSocket connections).

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
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken

logger = logging.getLogger(__name__)


class ChatConsumer(AsyncJsonWebsocketConsumer):

    async def connect(self):
        self.conversation_id = self.scope["url_route"]["kwargs"]["conversation_id"]
        self.group_name = f"chat_{self.conversation_id}"

        token = self._get_token_from_query()
        user = await self._authenticate(token)
        if user is None:
            await self.close(code=4001)
            return

        # Verify the user is a participant in this conversation
        is_participant = await self._is_participant(user, self.conversation_id)
        if not is_participant:
            await self.close(code=4003)
            return

        self.user = user
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.info(
            "ChatConsumer connected: user=%s conv=%s",
            user.id, self.conversation_id,
        )

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        msg_type = content.get("type")

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
        from apps.chat.models import Conversation
        try:
            conversation = await database_sync_to_async(
                Conversation.objects.get
            )(id=self.conversation_id)
        except Conversation.DoesNotExist:
            await self.send_json({"type": "error", "message": "Conversation not found."})
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
            from apps.users.models import User
            return await database_sync_to_async(User.objects.get)(id=user_id)
        except (InvalidToken, TokenError, Exception):
            return None

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

"""
Chat REST Views

Thin views — all business logic is in ChatService.
"""

import uuid
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from .serializers import ConversationSerializer, MessageSerializer
from .services import ChatService


class ConversationViewSet(ViewSet):
    """
    GET  /chat/conversations/      → list user's conversations
    POST /chat/conversations/dm/   → get or create DM
    GET  /chat/conversations/{id}/messages/  → message history
    POST /chat/conversations/{id}/read/      → mark all as read
    """
    permission_classes = [IsAuthenticated]

    def list(self, request):
        conversations = ChatService.get_user_conversations(request.user)
        serializer = ConversationSerializer(
            conversations, many=True, context={"request": request}
        )
        return Response({"success": True, "data": serializer.data})

    def create_dm(self, request):
        user_id = request.data.get("user_id")
        if not user_id:
            return Response(
                {"success": False, "error": {"message": "user_id is required."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            from apps.users.models import User
            other_user = User.objects.get(id=user_id)
        except (User.DoesNotExist, Exception):
            return Response(
                {"success": False, "error": {"message": "User not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        conversation = ChatService.get_or_create_dm(request.user, other_user)
        serializer = ConversationSerializer(conversation, context={"request": request})
        return Response(
            {"success": True, "data": serializer.data},
            status=status.HTTP_201_CREATED,
        )

    def list_messages(self, request, pk=None):
        try:
            from .models import Conversation
            conversation = Conversation.objects.get(id=pk)
        except (Conversation.DoesNotExist, Exception):
            return Response(
                {"success": False, "error": {"message": "Conversation not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        before_id = request.query_params.get("before")
        # Let PermissionDenied bubble up — DRF translates it to 403.
        messages = ChatService.get_messages(
            conversation, request.user,
            before_id=uuid.UUID(before_id) if before_id else None,
        )
        serializer = MessageSerializer(messages, many=True)
        return Response({"success": True, "data": serializer.data})

    def mark_read(self, request, pk=None):
        try:
            from .models import Conversation
            conversation = Conversation.objects.get(id=pk)
        except (Conversation.DoesNotExist, Exception):
            return Response(
                {"success": False, "error": {"message": "Conversation not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        count = ChatService.mark_conversation_read(conversation, request.user)
        return Response({"success": True, "data": {"marked_read": count}})


class NestConversationView(APIView):
    """GET /chat/nest/{nest_id}/conversation/ — get or create nest group chat."""
    permission_classes = [IsAuthenticated]

    def get(self, request, nest_id):
        try:
            from apps.nests.models import Nest
            nest = Nest.objects.get(id=nest_id)
        except (Exception,):
            return Response(
                {"success": False, "error": {"message": "Nest not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        conversation = ChatService.get_or_create_nest_conversation(nest)
        serializer = ConversationSerializer(conversation, context={"request": request})
        return Response({"success": True, "data": serializer.data})


class ChattableContactsView(APIView):
    """GET /chat/contacts/ — users the caller can start a DM with."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .serializers import UserMinimalSerializer
        contacts = ChatService.get_chattable_contacts(request.user)
        serializer = UserMinimalSerializer(contacts, many=True)
        return Response({"success": True, "data": serializer.data})

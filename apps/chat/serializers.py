"""Chat serializers — read-only output shapes for the REST API."""

from rest_framework import serializers

from apps.users.models import User
from .models import Conversation, Message


class UserMinimalSerializer(serializers.ModelSerializer):
    # User model has no get_full_name() method, so use SerializerMethodField.
    full_name = serializers.SerializerMethodField()

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()

    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "full_name", "role"]


class MessageSerializer(serializers.ModelSerializer):
    sender = UserMinimalSerializer(read_only=True)
    sender_id = serializers.UUIDField(source="sender.id", read_only=True)
    # is_deleted is a @property on SoftDeleteMixin, not a DB field.
    # Use SerializerMethodField so DRF reliably serializes it.
    is_deleted = serializers.SerializerMethodField()

    def get_is_deleted(self, obj):
        return obj.is_deleted  # reads SoftDeleteMixin @property

    class Meta:
        model = Message
        fields = [
            "id", "conversation", "sender", "sender_id",
            "content", "is_deleted", "created_at",
        ]
        read_only_fields = ["id", "conversation", "sender", "sender_id", "content", "created_at"]


class ConversationSerializer(serializers.ModelSerializer):
    participants = UserMinimalSerializer(many=True, read_only=True)
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    nest_name = serializers.CharField(source="nest.name", read_only=True, default=None)
    nest_id = serializers.UUIDField(source="nest.id", read_only=True, default=None)

    class Meta:
        model = Conversation
        fields = [
            "id", "conversation_type", "participants",
            "nest_id", "nest_name", "last_message",
            "unread_count", "created_at", "updated_at",
        ]

    def get_last_message(self, obj):
        msg = obj.messages.order_by("-created_at").first()
        if not msg:
            return None
        return {
            "id": str(msg.id),
            "content": msg.content if not msg.is_deleted else "[deleted]",
            "sender_id": str(msg.sender_id) if msg.sender_id else None,
            "created_at": msg.created_at.isoformat(),
        }

    def get_unread_count(self, obj):
        request = self.context.get("request")
        if not request:
            return 0
        from .services import ChatService
        return ChatService.get_unread_count(obj, request.user)

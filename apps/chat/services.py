"""
Chat Service

All business logic for conversations and messages.
Views and consumers delegate to this service — thin views, fat services.
"""

import logging
import uuid

from django.db import transaction
from rest_framework.exceptions import PermissionDenied, ValidationError

from .models import Conversation, Message, MessageRead

logger = logging.getLogger(__name__)


class ChatService:

    @staticmethod
    @transaction.atomic
    def get_or_create_dm(user_a, user_b) -> Conversation:
        """Return existing DM conversation or create one. Order-independent."""
        if user_a.id == user_b.id:
            raise ValidationError("Cannot start a conversation with yourself.")

        # Find existing DM between exactly these two users
        existing = (
            Conversation.objects
            .filter(conversation_type="direct")
            .filter(participants=user_a)
            .filter(participants=user_b)
        )
        for conv in existing:
            if conv.participants.count() == 2:
                return conv

        conv = Conversation.objects.create(conversation_type="direct")
        conv.participants.add(user_a, user_b)
        logger.info("DM created: %s <-> %s", user_a.email, user_b.email)
        return conv

    @staticmethod
    @transaction.atomic
    def get_or_create_nest_conversation(nest) -> Conversation:
        """Return the Nest group conversation or create it."""
        try:
            return nest.conversation
        except Conversation.DoesNotExist:
            pass

        conv = Conversation.objects.create(
            conversation_type="nest_group",
            nest=nest,
        )
        # Add all active nest members as participants
        from apps.nests.models import NestMembership
        members = (
            NestMembership.objects
            .filter(nest=nest, status="active")
            .values_list("user_id", flat=True)
        )
        conv.participants.set(members)
        logger.info("Nest group conversation created for Nest: %s", nest.name)
        return conv

    @staticmethod
    def get_user_conversations(user):
        """Return all conversations the user is a participant in, newest first."""
        return (
            Conversation.objects
            .filter(participants=user, is_active=True)
            .prefetch_related("participants")
            .select_related("nest")
            .order_by("-updated_at")
        )

    @staticmethod
    @transaction.atomic
    def create_message(conversation: Conversation, sender, content: str) -> Message:
        """Create a message. Validates sender is a participant and content is non-empty."""
        content = content.strip()
        if not content:
            raise ValidationError("Message content cannot be empty.")
        if len(content) > 4000:
            raise ValidationError("Message cannot exceed 4000 characters.")

        if not conversation.participants.filter(id=sender.id).exists():
            raise PermissionDenied("You are not a participant in this conversation.")

        msg = Message.objects.create(
            conversation=conversation,
            sender=sender,
            content=content,
        )
        # Touch the conversation so it sorts to top.
        # updated_at uses auto_now=True, so we call save() to trigger it.
        conversation.save(update_fields=["updated_at"])
        return msg

    @staticmethod
    def get_messages(
        conversation: Conversation,
        user,
        before_id: uuid.UUID = None,
        limit: int = 50,
    ):
        """
        Return messages in chronological order (oldest first).
        before_id: cursor for pagination — return messages before this message.
        """
        if not conversation.participants.filter(id=user.id).exists():
            raise PermissionDenied("You are not a participant in this conversation.")

        qs = Message.objects.filter(conversation=conversation)

        if before_id:
            try:
                anchor = Message.objects.get(id=before_id)
                qs = qs.filter(created_at__lt=anchor.created_at)
            except Message.DoesNotExist:
                pass

        return qs.select_related("sender").order_by("created_at")[:limit]

    @staticmethod
    @transaction.atomic
    def mark_conversation_read(conversation: Conversation, user) -> int:
        """
        Bulk-create MessageRead records for all unread messages in the conversation.
        Returns count of newly marked messages.
        """
        already_read = MessageRead.objects.filter(
            user=user,
            message__conversation=conversation,
        ).values_list("message_id", flat=True)

        unread = Message.objects.filter(
            conversation=conversation,
        ).exclude(id__in=already_read)

        reads = [MessageRead(message=msg, user=user) for msg in unread]
        MessageRead.objects.bulk_create(reads, ignore_conflicts=True)
        return len(reads)

    @staticmethod
    def get_unread_count(conversation: Conversation, user) -> int:
        """Count messages in conversation not yet read by user."""
        read_ids = MessageRead.objects.filter(
            user=user,
            message__conversation=conversation,
        ).values_list("message_id", flat=True)
        return Message.objects.filter(
            conversation=conversation,
        ).exclude(id__in=read_ids).count()

    @staticmethod
    def get_chattable_contacts(user):
        """
        Return users the logged-in user is allowed to message.
        - Admin  → all other active users
        - Eagle  → eaglets who are active members of this eagle's nests
        - Eaglet → nest eagles (mentors), admins, and peers in shared nests
        """
        from apps.users.models import User
        from apps.nests.models import Nest, NestMembership

        if user.role == "admin":
            return User.objects.exclude(id=user.id).filter(is_active=True)

        if user.role == "eagle":
            nest_ids = Nest.objects.filter(
                eagle=user, is_active=True
            ).values_list("id", flat=True)
            eaglet_ids = (
                NestMembership.objects.filter(nest_id__in=nest_ids, status="active")
                .exclude(user=user)
                .values_list("user_id", flat=True)
            )
            return User.objects.filter(id__in=eaglet_ids, is_active=True)

        # Eaglet
        my_nest_ids = NestMembership.objects.filter(
            user=user, status="active"
        ).values_list("nest_id", flat=True)
        eagle_ids = Nest.objects.filter(
            id__in=my_nest_ids, is_active=True
        ).values_list("eagle_id", flat=True)
        peer_ids = (
            NestMembership.objects.filter(nest_id__in=my_nest_ids, status="active")
            .exclude(user=user)
            .values_list("user_id", flat=True)
        )
        admin_ids = User.objects.filter(
            role="admin", is_active=True
        ).values_list("id", flat=True)
        all_ids = set(eagle_ids) | set(peer_ids) | set(admin_ids)
        return User.objects.filter(id__in=all_ids, is_active=True)

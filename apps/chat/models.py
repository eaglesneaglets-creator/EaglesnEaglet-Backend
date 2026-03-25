"""
Chat Models

Conversation: DM or Nest group chat container.
Message: Individual message within a conversation.
MessageRead: Tracks which users have read which messages.
"""

import uuid

from django.conf import settings
from django.db import models

from core.mixins.timestamp import TimestampMixin
from core.mixins.soft_delete import SoftDeleteMixin


class Conversation(TimestampMixin, models.Model):
    """A chat thread — either a 1-on-1 DM or a Nest group chat."""

    class Type(models.TextChoices):
        DIRECT = "direct", "Direct Message"
        NEST_GROUP = "nest_group", "Nest Group"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation_type = models.CharField(max_length=20, choices=Type.choices)
    participants = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="conversations",
        blank=True,
    )
    # Only set for nest_group conversations
    nest = models.OneToOneField(
        "nests.Nest",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="conversation",
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["conversation_type"]),
        ]

    def __str__(self):
        if self.nest:
            return f"Nest:{self.nest.name}"
        return f"DM:{self.id}"


class Message(SoftDeleteMixin, TimestampMixin, models.Model):
    """A single message in a conversation."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name="messages",
    )
    # SET_NULL so we don't lose messages when a user is deleted
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="sent_messages",
    )
    content = models.TextField(max_length=4000)
    # NOTE: do NOT add an is_deleted BooleanField here.
    # SoftDeleteMixin already provides `is_deleted` as a @property
    # (returns `deleted_at is not None`). Adding a BooleanField would
    # shadow that property and create divergent state on restore().

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["conversation", "created_at"]),
        ]

    def __str__(self):
        return f"Message({self.id}) in {self.conversation_id}"
    # No soft_delete() override — SoftDeleteMixin.soft_delete() is sufficient.


class MessageRead(models.Model):
    """Records when a user read a specific message."""

    message = models.ForeignKey(
        Message,
        on_delete=models.CASCADE,
        related_name="read_receipts",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="read_messages",
    )
    read_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("message", "user")]
        indexes = [
            models.Index(fields=["message", "user"]),
        ]

    def __str__(self):
        return f"{self.user} read {self.message_id}"

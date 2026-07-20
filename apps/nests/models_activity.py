"""
NestActivity — admin-facing audit trail for a Nest (Phase 27-01).

Records member joins/leaves/removals, content shared, posts, and admin/mentor
actions (nest created, archived). Surfaced in the admin nest-detail "Activity"
tab. This is an AUDIT log — NOT private chat messages (privacy decision D2).

Kept in its own module (mirrors models_program.py / models_admin.py) and
re-exported from models.py so `from apps.nests.models import NestActivity`
works everywhere.
"""

import uuid

from django.conf import settings
from django.db import models

from core.mixins import TimestampMixin

from .models import Nest


class NestActivity(TimestampMixin, models.Model):
    """A single audit-log entry for a Nest."""

    class ActionType(models.TextChoices):
        MEMBER_JOINED = "member_joined", "Member joined"
        MEMBER_LEFT = "member_left", "Member left"
        MEMBER_REMOVED = "member_removed", "Member removed"
        CONTENT_SHARED = "content_shared", "Content shared"
        POST_CREATED = "post_created", "Post created"
        NEST_CREATED = "nest_created", "Nest created"
        NEST_ARCHIVED = "nest_archived", "Nest archived"
        MENTOR_ACTION = "mentor_action", "Mentor action"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nest = models.ForeignKey(
        Nest,
        on_delete=models.CASCADE,
        related_name="activities",
    )
    # Null actor = system-generated event (e.g. signal with no request user).
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="nest_activities",
    )
    action_type = models.CharField(
        max_length=20,
        choices=ActionType.choices,
    )
    # Human-readable description of the target (e.g. "Sarah Jenkins",
    # "Ethical Leadership.pdf"). Denormalised so the log survives target deletion.
    target = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "nest_activities"
        ordering = ["-created_at"]
        verbose_name_plural = "Nest activities"
        indexes = [
            models.Index(fields=["nest", "-created_at"]),
            models.Index(fields=["action_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.action_type} @ {self.nest_id} ({self.created_at:%Y-%m-%d})"

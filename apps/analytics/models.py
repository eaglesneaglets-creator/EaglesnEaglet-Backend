"""
Analytics Models

Lightweight engagement tracking for dashboard aggregation and reporting.
"""

import uuid

from django.conf import settings
from django.db import models

from core.mixins import TimestampMixin


class EngagementLog(TimestampMixin, models.Model):
    """
    Records user actions for analytics aggregation.
    Used to generate dashboard stats and trend reports.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="engagement_logs",
    )
    action = models.CharField(
        max_length=50,
        help_text="E.g. 'login', 'content_view', 'post_created'.",
    )
    target_type = models.CharField(
        max_length=30, blank=True,
        help_text="Model name: 'nest', 'content_item', 'assignment'.",
    )
    target_id = models.UUIDField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "engagement_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["action", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.user} — {self.action} ({self.created_at:%Y-%m-%d})"

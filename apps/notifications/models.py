"""
Notification Models

In-app notification system for mentorship requests, approvals,
content updates, and point awards.
"""

import uuid

from django.conf import settings
from django.db import models


class Notification(models.Model):
    """In-app notification for a user."""

    class NotificationType(models.TextChoices):
        MENTORSHIP_REQUEST = "mentorship_request", "Mentorship Request"
        MENTORSHIP_APPROVED = "mentorship_approved", "Mentorship Approved"
        MENTORSHIP_REJECTED = "mentorship_rejected", "Mentorship Rejected"
        CONTENT_PUBLISHED = "content_published", "Content Published"
        POINTS_AWARDED = "points_awarded", "Points Awarded"
        BADGE_EARNED = "badge_earned", "Badge Earned"
        NEST_POST = "nest_post", "Nest Post"
        ASSIGNMENT_GRADED = "assignment_graded", "Assignment Graded"
        GENERAL = "general", "General"
        POST_LIKE = "post_like", "Post Liked"
        POST_COMMENT = "post_comment", "Post Commented"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    notification_type = models.CharField(
        max_length=30,
        choices=NotificationType.choices,
        default=NotificationType.GENERAL,
    )
    title = models.CharField(max_length=200)
    message = models.TextField(max_length=500)
    is_read = models.BooleanField(default=False)

    # Optional link to the relevant object
    action_url = models.CharField(max_length=500, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["recipient", "-created_at"]),
            models.Index(fields=["recipient", "is_read"]),
        ]

    def __str__(self):
        return f"{self.notification_type} → {self.recipient}"

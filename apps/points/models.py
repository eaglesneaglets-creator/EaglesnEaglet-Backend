"""
Points Models

Gamification system: point transactions (append-only ledger), badges,
leaderboard, and configurable point values per activity type.
"""

import uuid

from django.conf import settings
from django.db import models

from core.mixins import TimestampMixin


# ---------------------------------------------------------------------------
# Point Configuration — admin-configurable point values
# ---------------------------------------------------------------------------

class PointConfiguration(TimestampMixin, models.Model):
    """
    Configurable point values per activity type.
    Admin can enable/disable and adjust points.
    """

    ACTIVITY_CHOICES = [
        ("video_complete", "Video Completed"),
        ("document_read", "Document Read"),
        ("assignment_submit", "Assignment Submitted"),
        ("assignment_graded", "Assignment Graded"),
        ("module_complete", "Module Completed"),
        ("check_in", "Daily Check-In"),
        ("post_created", "Post Created"),
        ("resource_shared", "Resource Shared"),
        ("event_attended", "Event Attended"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    activity_type = models.CharField(
        max_length=30, unique=True, choices=ACTIVITY_CHOICES
    )
    points_value = models.PositiveIntegerField(default=10)
    is_active = models.BooleanField(default=True)
    description = models.CharField(max_length=200, blank=True)

    class Meta:
        db_table = "point_configurations"
        ordering = ["activity_type"]

    def __str__(self) -> str:
        return f"{self.get_activity_type_display()}: {self.points_value}pts"


# ---------------------------------------------------------------------------
# Point Transaction — immutable ledger
# ---------------------------------------------------------------------------

class PointTransaction(TimestampMixin, models.Model):
    """
    Immutable record of points earned or spent.
    Never update or delete — append only.
    """

    class Source(models.TextChoices):
        AUTO = "auto", "Automatic"
        MANUAL = "manual", "Manual Award"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="point_transactions",
    )
    points = models.IntegerField(help_text="Positive for earn, negative for spend.")
    activity_type = models.CharField(max_length=30)
    source = models.CharField(
        max_length=10,
        choices=Source.choices,
        default=Source.AUTO,
    )
    source_id = models.UUIDField(
        null=True, blank=True,
        help_text="ID of the entity that triggered this (content item, etc.)",
    )
    description = models.CharField(max_length=250, blank=True)
    awarded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="points_awarded",
    )
    nest = models.ForeignKey(
        "nests.Nest",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="point_transactions",
    )

    class Meta:
        db_table = "point_transactions"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["user", "activity_type"]),
            models.Index(fields=["nest", "user"]),
            models.Index(fields=["activity_type", "created_at"]),  # New for aggregation
            models.Index(fields=["-created_at"]), # General sorting/recent filtering
        ]

    def __str__(self) -> str:
        sign = "+" if self.points > 0 else ""
        return f"{self.user}: {sign}{self.points} ({self.activity_type})"


# ---------------------------------------------------------------------------
# Badge
# ---------------------------------------------------------------------------

class Badge(TimestampMixin, models.Model):
    """Achievement badge that users can earn."""

    class CriteriaType(models.TextChoices):
        POINTS_THRESHOLD = "points_threshold", "Points Threshold"
        COURSES_COMPLETED = "courses_completed", "Courses Completed"
        STREAK_DAYS = "streak_days", "Streak Days"
        ASSIGNMENTS_SUBMITTED = "assignments_submitted", "Assignments Submitted"
        COMMUNITY_CONTRIBUTIONS = "community_contributions", "Community Contributions"
        QUIZZES_PASSED = "quizzes_passed", "Quizzes Passed"
        EVENTS_ATTENDED = "events_attended", "Events Attended"
        NESTS_JOINED = "nests_joined", "Nests Joined"
        ONE_TIME_EVENT = "one_time_event", "One-Time Event"
        COMPETITIVE = "competitive", "Competitive"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    icon = models.URLField(max_length=2000, blank=True)  # extended for SVG data URIs
    slug = models.SlugField(max_length=60, unique=True, blank=True, default="")
    criteria_type = models.CharField(
        max_length=30, choices=CriteriaType.choices
    )
    criteria_value = models.PositiveIntegerField(
        help_text="Numeric threshold for earning this badge."
    )

    class Meta:
        db_table = "badges"
        ordering = ["criteria_value"]

    def __str__(self) -> str:
        return self.name


class UserBadge(TimestampMixin, models.Model):
    """Records that a user has earned a badge."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="badges",
    )
    badge = models.ForeignKey(
        Badge, on_delete=models.CASCADE, related_name="earners"
    )
    earned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_badges"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "badge"],
                name="unique_user_badge",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.user} earned {self.badge.name}"

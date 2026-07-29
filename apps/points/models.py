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
# Points Policy — governance for MANUAL awards (Phase 31-01)
# ---------------------------------------------------------------------------

class PointsPolicy(TimestampMixin, models.Model):
    """Superadmin-controlled limits on manual point awards. Singleton (pk=1).

    `PointConfiguration` above governs AUTOMATIC awards (one row per activity
    type). It has no bearing on what a mentor can hand out by hand — before this
    model, manual awards were bounded only by a hardcoded `max_value=1000` in
    `ManualPointAwardSerializer`, with no rate limit at all, making 1000 points a
    per-click figure. Since points drive `MenteeLevelConfig` thresholds and Level 5
    sets `unlocks_mentor_application`, that was a route to manufacturing mentor
    candidates.

    Enforced in `PointService.award_manual_points()` — the single chokepoint every
    caller passes through — NOT in the serializer (which any non-API caller bypasses).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    max_manual_award = models.PositiveIntegerField(
        default=25,
        help_text="Maximum points a mentor may award in a single transaction.",
    )
    daily_points_per_mentor = models.PositiveIntegerField(
        default=250,
        help_text="Maximum total points a mentor may award per day (UTC).",
    )
    is_enforced = models.BooleanField(
        default=True,
        help_text="Escape hatch — uncheck to suspend limits during an incident.",
    )

    class Meta:
        db_table = "points_policy"
        verbose_name_plural = "Points policies"

    def __str__(self) -> str:
        state = "enforced" if self.is_enforced else "DISABLED"
        return (
            f"Points policy ({state}): max {self.max_manual_award}/award, "
            f"{self.daily_points_per_mentor}/mentor/day"
        )

    @classmethod
    def load(cls):
        """Return the singleton policy row, creating it with defaults if absent.

        Callers never have to handle a missing row — important because the award
        path reads this on every manual award.
        """
        policy = cls.objects.first()
        if policy is None:
            policy = cls.objects.create()
        return policy


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
            # Phase 31-01: the per-mentor daily budget is summed from this ledger on
            # EVERY manual award, filtered by awarder + date. Without this index that
            # is a seq-scan over a table that only ever grows.
            models.Index(fields=["awarded_by", "-created_at"]),
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
    icon = models.TextField(blank=True)  # stores SVG data URIs (data:image/svg+xml,...)
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
        db_index=True,
    )
    badge = models.ForeignKey(
        Badge, on_delete=models.CASCADE, related_name="earners",
        db_index=True,
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
        indexes = [
            models.Index(fields=["user", "-earned_at"]),   # fetch user's badges sorted by date
        ]

    def __str__(self) -> str:
        return f"{self.user} earned {self.badge.name}"

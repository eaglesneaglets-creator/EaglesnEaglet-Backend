"""
Program Models

A Program is a structured mentorship engagement inside a Nest. Each Nest has
at most one program with status='active' at a time (v1 single-active-program rule,
enforced by partial unique index).

Mentees enroll in programs (see ProgramEnrollment in plan 14-02), not in Nests
directly. This module ships only the program *definition* — enrollment and
progress evaluation arrive in 14-02 and 14-03 respectively.
"""

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from core.mixins import SoftDeleteMixin, TimestampMixin

from .models import Nest


# ---------------------------------------------------------------------------
# Program — the structured engagement inside a Nest
# ---------------------------------------------------------------------------


class Program(SoftDeleteMixin, TimestampMixin, models.Model):
    """A versioned engagement template owned by a Nest."""

    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        ACTIVE = "active", "Active"
        ARCHIVED = "archived", "Archived"

    # Allowed status transitions. Reverse moves are rejected in clean().
    _ALLOWED_TRANSITIONS = {
        Status.DRAFT: {Status.DRAFT, Status.ACTIVE, Status.ARCHIVED},
        Status.ACTIVE: {Status.ACTIVE, Status.ARCHIVED},
        Status.ARCHIVED: {Status.ARCHIVED},
    }

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nest = models.ForeignKey(
        Nest,
        on_delete=models.CASCADE,
        related_name="programs",
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT,
        db_index=True,
    )
    activated_at = models.DateTimeField(null=True, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="programs_created",
    )

    class Meta:
        db_table = "nest_programs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["nest", "status"]),
        ]
        constraints = [
            # At most ONE active program per Nest (Postgres partial unique index).
            # SQLite ignores the WHERE clause and would refuse two rows in any
            # status — tests use distinct nests for non-active fixtures.
            models.UniqueConstraint(
                fields=["nest"],
                condition=models.Q(status="active"),
                name="uniq_active_program_per_nest",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.nest.name} — {self.status})"

    def clean(self) -> None:
        super().clean()
        if not self.pk:
            return
        previous = type(self).objects.only("status").get(pk=self.pk).status
        allowed = self._ALLOWED_TRANSITIONS.get(previous, set())
        if self.status not in allowed:
            raise ValidationError(
                {"status": f"Invalid status transition: {previous} → {self.status}"}
            )


# ---------------------------------------------------------------------------
# ProgramObjective — a measurable goal the mentee must complete
# ---------------------------------------------------------------------------


class ProgramObjective(TimestampMixin, models.Model):
    """A goal attached to a Program. v1: ALL objectives required for completion."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    program = models.ForeignKey(
        Program,
        on_delete=models.CASCADE,
        related_name="objectives",
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    order = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = "nest_program_objectives"
        ordering = ["program", "order", "created_at"]
        indexes = [
            models.Index(fields=["program"]),
        ]

    def __str__(self) -> str:
        return f"{self.program.name} — {self.title}"


# ---------------------------------------------------------------------------
# ProgramObjectiveRule — the measurable rule attached to an objective
# ---------------------------------------------------------------------------


class ProgramObjectiveRule(TimestampMixin, models.Model):
    """
    One measurable rule attached to a ProgramObjective. v1 supports 5 rule
    types (locked decision); evaluator implementations land in plan 14-03.
    """

    class RuleType(models.TextChoices):
        MODULES_COMPLETED = "modules_completed", "Modules completed"
        ASSIGNMENTS_PASSED = "assignments_passed", "Assignments passed"
        POINTS_EARNED = "points_earned", "Points earned"
        POSTS_COUNT = "posts_count", "Community posts"
        STREAK_DAYS = "streak_days", "Activity streak (days)"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    objective = models.ForeignKey(
        ProgramObjective,
        on_delete=models.CASCADE,
        related_name="rules",
    )
    rule_type = models.CharField(max_length=40, choices=RuleType.choices)
    target = models.PositiveIntegerField(
        help_text="Numeric threshold the mentee must hit (e.g. 5 modules, 1000 points)."
    )
    config = models.JSONField(
        default=dict,
        blank=True,
        help_text="Rule-specific params (e.g. {'module_ids': [...]} for scoped rules).",
    )

    class Meta:
        db_table = "nest_program_objective_rules"
        ordering = ["objective", "id"]
        indexes = [
            models.Index(fields=["objective", "rule_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.rule_type}={self.target}"

    def clean(self) -> None:
        super().clean()
        if self.target is not None and self.target < 1:
            raise ValidationError({"target": "Target must be at least 1."})
        if not isinstance(self.config, dict):
            raise ValidationError({"config": "Config must be a JSON object."})


# ---------------------------------------------------------------------------
# ProgramEnrollment — mentee's lifecycle record for one Program (plan 14-02)
# ---------------------------------------------------------------------------


class ProgramEnrollment(TimestampMixin, models.Model):
    """
    Mentee's lifecycle record for one Program. v1 invariants enforced via
    partial unique indexes (Postgres) AND service-layer checks (cross-DB):
      - At most ONE pending enrollment per mentee (any program)
      - At most ONE active enrollment per mentee (any program)

    Status transitions are NOT validated in clean() because they depend on the
    actor (mentor vs mentee vs admin). EnrollmentService is the source of truth.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        COMPLETED = "completed", "Completed"
        RELEASED = "released", "Released"
        OPTED_OUT = "opted_out", "Opted out"
        REJECTED = "rejected", "Rejected"

    _TERMINAL_STATUSES = {
        Status.COMPLETED,
        Status.RELEASED,
        Status.OPTED_OUT,
        Status.REJECTED,
    }

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    program = models.ForeignKey(
        Program,
        on_delete=models.PROTECT,
        related_name="enrollments",
    )
    mentee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="program_enrollments",
        limit_choices_to={"role": "eaglet"},
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )

    application_message = models.TextField(blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)

    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="enrollments_reviewed",
    )
    ended_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="enrollments_ended",
    )
    exit_reason = models.TextField(blank=True)

    rules_snapshot = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "nest_program_enrollments"
        ordering = ["-requested_at"]
        indexes = [
            models.Index(fields=["mentee", "status"]),
            models.Index(fields=["program", "status"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["mentee"],
                condition=models.Q(status="pending"),
                name="uniq_pending_enrollment_per_mentee",
            ),
            models.UniqueConstraint(
                fields=["mentee"],
                condition=models.Q(status="active"),
                name="uniq_active_enrollment_per_mentee",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.mentee_id} → {self.program.name} [{self.status}]"

    @property
    def is_terminal(self) -> bool:
        return self.status in self._TERMINAL_STATUSES


# ---------------------------------------------------------------------------
# ProgramExitRequest — mentee-initiated opt-out (mentor finalizes)
# ---------------------------------------------------------------------------


class ProgramExitRequest(TimestampMixin, models.Model):
    """
    Mentee-initiated request to exit an active enrollment. Mentor finalizes
    via approve/deny — mentee cannot self-finalize (locked design decision).

    State machine: pending → (approved | denied)
    Approval routes through EnrollmentService.decide_opt_out which transitions
    the parent enrollment to OPTED_OUT.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        DENIED = "denied", "Denied"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    enrollment = models.ForeignKey(
        ProgramEnrollment,
        on_delete=models.CASCADE,
        related_name="exit_requests",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="exit_requests_made",
    )
    reason = models.TextField()
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="exit_requests_decided",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.TextField(blank=True)

    class Meta:
        db_table = "nest_program_exit_requests"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["enrollment"],
                condition=models.Q(status="pending"),
                name="uniq_pending_exit_per_enrollment",
            ),
        ]

    def __str__(self) -> str:
        return f"ExitRequest({self.enrollment_id}, {self.status})"


# ---------------------------------------------------------------------------
# MenteeLevelConfig — admin-editable progression thresholds (plan 14-04)
# ---------------------------------------------------------------------------


class MenteeLevelConfig(TimestampMixin, models.Model):
    """One row per progression tier (1..5). Seeded by migration 0010."""

    level = models.PositiveSmallIntegerField(unique=True)
    name = models.CharField(max_length=64)
    points_required = models.PositiveIntegerField()
    unlocks_mentor_application = models.BooleanField(default=False)
    description = models.TextField(blank=True)

    class Meta:
        db_table = "mentee_level_configs"
        ordering = ["level"]
        constraints = [
            models.CheckConstraint(
                check=models.Q(level__gte=1) & models.Q(level__lte=5),
                name="mentee_level_in_range_1_5",
            ),
        ]

    def __str__(self) -> str:
        return f"L{self.level} {self.name} ({self.points_required}pts)"

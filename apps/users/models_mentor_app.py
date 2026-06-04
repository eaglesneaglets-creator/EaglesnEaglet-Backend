"""
Mentor Application models (plan 16-01).

A Level-5 Eaglet can apply to become a mentor. On approval the user's role is
flipped to EAGLE (decision 16-01: flip-role); mentee level/program history lives
in separate tables and is preserved.

  * MentorApplication       — the application + lifecycle status.
  * MentorApplicationAudit  — immutable audit row of every transition.

Mirrors the Phase 18 admin-role pattern (models_admin.py).
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q

from core.mixins.timestamp import TimestampMixin


class MentorApplication(TimestampMixin, models.Model):
    """A mentee's self-service application to gain the mentor (Eagle) role."""

    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        SUBMITTED = "submitted", "Submitted"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        WITHDRAWN = "withdrawn", "Withdrawn"

    # Active = occupies the "one application per user" slot.
    ACTIVE_STATUSES = (Status.DRAFT, Status.SUBMITTED, Status.APPROVED)

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="mentor_applications",
        on_delete=models.CASCADE,
    )
    # The MentorKYC record the applicant completes/reuses. Nullable so a draft can
    # exist before KYC is linked. apps.users.models.MentorKYC.
    mentor_kyc = models.ForeignKey(
        "users.MentorKYC",
        related_name="mentor_applications",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    status = models.CharField(
        max_length=12,
        choices=Status.choices,
        default=Status.DRAFT,
        db_index=True,
    )

    submitted_at = models.DateTimeField(null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="mentor_application_decisions",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    rejection_reason = models.TextField(blank=True, max_length=2000)
    review_notes = models.TextField(blank=True, max_length=2000)

    class Meta:
        db_table = "mentor_applications"
        ordering = ["-created_at"]
        constraints = [
            # At most one active (draft/submitted/approved) application per user.
            models.UniqueConstraint(
                fields=["user"],
                condition=Q(status__in=["draft", "submitted", "approved"]),
                name="one_active_mentor_application_per_user",
            ),
        ]

    def __str__(self) -> str:
        return f"MentorApplication({self.user_id}, {self.status})"


class MentorApplicationAudit(models.Model):
    """Immutable audit row of a mentor-application transition.

    Insert-only (mirrors AdminRoleAudit): updates + deletes are blocked. Rows keep
    the actor via SET_NULL but cascade with the target application.
    """

    class Action(models.TextChoices):
        SUBMITTED = "submitted", "Submitted"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        WITHDRAWN = "withdrawn", "Withdrawn"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        MentorApplication,
        related_name="audit_entries",
        on_delete=models.CASCADE,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="+",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="User who performed the action. NULL for system-driven events.",
    )
    action = models.CharField(max_length=20, choices=Action.choices, db_index=True)
    reason = models.TextField(blank=True, max_length=2000)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "mentor_application_audit"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"MentorApplicationAudit({self.application_id}, {self.action})"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise RuntimeError("MentorApplicationAudit rows are immutable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise RuntimeError("MentorApplicationAudit rows are immutable.")

"""
Admin Role Management models (plan 18-01).

Three concerns:
  * AdminRoleRequest — Expression of Interest from a mentor.
  * AdminInvite      — Direct invite-by-email path from existing admin.
  * AdminRoleAudit   — Immutable audit log of every grant/revoke event.

The User model itself gains one new boolean (`is_platform_staff`) that
stacks on top of `role` — see migration 00XX_admin_role.py for the
backfill of existing admins.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from core.mixins.timestamp import TimestampMixin


def _generate_invite_token() -> str:
    """URL-safe 48-char token. Enough entropy for a 48-hour invite."""
    return secrets.token_urlsafe(36)


def hash_invite_token(raw: str) -> str:
    """SHA-256 hash of an invite token — what we store at rest.

    The raw token is sent in the invite email and shown ONCE on the admin
    UI at creation. After that, only the hash survives in the DB so an
    insider read of `admin_invites` cannot resurrect grant-power tokens.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _invite_default_expiry():
    # 48-hour window — short enough to feel urgent, long enough to span a
    # weekend if sent on a Friday. Revoke + reissue covers edge cases.
    return timezone.now() + timedelta(hours=48)


class AdminRoleRequest(TimestampMixin, models.Model):
    """Self-service EOI from a qualified mentor to gain admin role."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        WITHDRAWN = "withdrawn", "Withdrawn"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="admin_role_requests",
        on_delete=models.CASCADE,
    )
    reason = models.TextField(
        max_length=2000,
        help_text="Why the mentor wants to take on admin responsibilities (≥50 chars).",
    )
    status = models.CharField(
        max_length=12,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )

    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="admin_role_decisions",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.TextField(blank=True, max_length=1000)

    class Meta:
        db_table = "admin_role_requests"
        ordering = ["-created_at"]
        constraints = [
            # At most one pending request per user — keeps the queue clean
            # and matches the eligibility check.
            models.UniqueConstraint(
                fields=["user"],
                condition=Q(status="pending"),
                name="one_pending_admin_request_per_user",
            ),
        ]

    def __str__(self) -> str:
        return f"AdminRoleRequest({self.user_id}, {self.status})"


class AdminInvite(TimestampMixin, models.Model):
    """Admin-issued invite for a specific email to gain admin role."""

    class Status(models.TextChoices):
        SENT = "sent", "Sent"
        ACCEPTED = "accepted", "Accepted"
        EXPIRED = "expired", "Expired"
        REVOKED = "revoked", "Revoked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(db_index=True)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="admin_invites_sent",
        on_delete=models.SET_NULL,
        null=True,
    )
    # Only the SHA-256 hash sits at rest. The raw token is generated in the
    # service layer at create time, attached to the email link + returned
    # ONCE to the admin who issued the invite, then thrown away.
    token_hash = models.CharField(
        max_length=64,
        unique=True,
        editable=False,
        # unique=True already creates the index — db_index would duplicate it.
    )
    status = models.CharField(
        max_length=12,
        choices=Status.choices,
        default=Status.SENT,
        db_index=True,
    )
    expires_at = models.DateTimeField(default=_invite_default_expiry)
    accepted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="admin_invites_accepted",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    accepted_at = models.DateTimeField(null=True, blank=True)

    # Optional personal note included in the invite email.
    message = models.TextField(blank=True, max_length=500)

    class Meta:
        db_table = "admin_invites"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"AdminInvite({self.email}, {self.status})"

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at


class AdminRoleAudit(models.Model):
    """
    Immutable audit row of an admin-role grant or revocation.

    Insert-only: the model manager forbids `.save()` on existing rows
    and the table omits an `updated_at` column on purpose. Rows survive
    deletion of the actor (FK SET_NULL) but cascade with the target so
    deletion of a user removes their audit trail entirely (privacy).
    """

    class Action(models.TextChoices):
        GRANTED = "granted", "Granted"
        REVOKED = "revoked", "Revoked"
        SELF_REVOKED = "self_revoked", "Self-revoked"
        SYSTEM_REVOKED = "system_revoked", "System-revoked"

    class Source(models.TextChoices):
        EOI = "eoi", "Expression of Interest"
        INVITE = "invite", "Direct invite"
        MANUAL = "manual", "Manual (CLI / migration)"
        SYSTEM = "system", "System action"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="+",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="User who performed the action. NULL for system-driven events.",
    )
    target = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="admin_role_audit_entries",
        on_delete=models.CASCADE,
    )
    action = models.CharField(max_length=20, choices=Action.choices, db_index=True)
    source = models.CharField(max_length=20, choices=Source.choices)
    reason = models.TextField(blank=True, max_length=2000)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "admin_role_audit"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"AdminRoleAudit({self.target_id}, {self.action})"

    def save(self, *args, **kwargs):
        # `_state.adding` is True on first save (insert), False on update.
        # Can't use `pk is not None` because UUIDField defaults assign one
        # immediately. Audit rows are insert-only — block updates here.
        if not self._state.adding:
            raise RuntimeError("AdminRoleAudit rows are immutable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise RuntimeError("AdminRoleAudit rows are immutable.")

"""
Mentor application service (plan 16-01).

Pure functions for the mentor-application lifecycle, mirroring services/admin_role.py.
Eligibility is gated on the mentee's Level-5 `unlocks_mentor_application` flag
(via nests.levels.compute_level). Approval flips the user's role to EAGLE
(decision 16-01: flip-role); mentee level/program history is in separate tables
and is preserved.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.users.models import User
from apps.users.models_mentor_app import (
    MentorApplication,
    MentorApplicationAudit,
)

logger = logging.getLogger(__name__)


class MentorApplicationError(Exception):
    """Domain error for invalid mentor-application transitions."""


class MentorApplicationCooldownError(MentorApplicationError):
    """Raised when an applicant tries to re-apply during the rejection cooldown."""

    def __init__(self, available_at):
        self.available_at = available_at
        super().__init__(
            f"You can re-apply after {available_at:%B %d, %Y}."
        )


def is_eligible(user) -> bool:
    """True if the user's current mentee level unlocks the mentor application."""
    # Local import avoids a users→nests import cycle at module load.
    from apps.nests.levels import compute_level

    if user.role != User.Role.EAGLET:
        return False
    try:
        return bool(compute_level(user).get("mentor_eligible"))
    except Exception:
        return False


def _audit(application, *, actor, action, reason=""):
    MentorApplicationAudit.objects.create(
        application=application,
        actor=actor,
        action=action,
        reason=(reason or "").strip()[:2000],
    )


def _cooldown_days() -> int:
    return int(getattr(settings, "MENTOR_APPLICATION_REJECT_COOLDOWN_DAYS", 30))


def _check_reject_cooldown(user) -> None:
    """Raise MentorApplicationCooldownError if the user is still within the
    post-rejection cooldown window. Looks at the most recent rejected row;
    withdrawn rows have no cooldown."""
    days = _cooldown_days()
    if days <= 0:
        return
    last_rejected = (
        MentorApplication.objects
        .filter(user=user, status=MentorApplication.Status.REJECTED)
        .order_by("-reviewed_at")
        .values("reviewed_at")
        .first()
    )
    if not last_rejected or not last_rejected["reviewed_at"]:
        return
    available_at = last_rejected["reviewed_at"] + timedelta(days=days)
    if timezone.now() < available_at:
        raise MentorApplicationCooldownError(available_at)


def _frontend_url() -> str:
    return getattr(settings, "FRONTEND_URL", "https://eaglesneaglets.com").rstrip("/")


def _send_themed_email(*, subject, template, context, recipients):
    """Render a themed HTML email and send. Failures never raise."""
    if not recipients:
        return
    try:
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.utils.html import strip_tags

        html_message = render_to_string(template, {
            "frontend_url": _frontend_url(),
            **context,
        })
        text_message = strip_tags(html_message)
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            html_message=html_message,
            fail_silently=True,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("mentor-application email send failed: %s", e)


def _notify_decision(app: MentorApplication, *, approved: bool) -> None:
    target = app.user
    if not target.email:
        return
    if approved:
        _send_themed_email(
            subject="You're now a mentor on Eagles & Eaglets",
            template="emails/mentor_application_approved.html",
            context={
                "first_name": target.first_name,
                "note": app.review_notes,
                "dashboard_url": f"{_frontend_url()}/eagle/dashboard",
            },
            recipients=[target.email],
        )
    else:
        cooldown_until = (app.reviewed_at or timezone.now()) + timedelta(
            days=_cooldown_days()
        )
        _send_themed_email(
            subject="Update on your mentor application",
            template="emails/mentor_application_rejected.html",
            context={
                "first_name": target.first_name,
                "reason": app.rejection_reason,
                "cooldown_until": cooldown_until,
                "cooldown_days": _cooldown_days(),
                "dashboard_url": f"{_frontend_url()}/eaglet/dashboard",
            },
            recipients=[target.email],
        )


def submit(*, user, mentor_kyc=None) -> MentorApplication:
    """Create + submit an application for an eligible Eaglet.

    Reuses an existing active draft if present; enforces eligibility and the
    one-active-application-per-user rule.
    """
    if not is_eligible(user):
        raise MentorApplicationError(
            "You are not yet eligible to apply — reach the mentor-eligible level first."
        )

    # Post-rejection cooldown: blocks re-apply for N days after a rejected
    # decision (settings.MENTOR_APPLICATION_REJECT_COOLDOWN_DAYS).
    _check_reject_cooldown(user)

    with transaction.atomic():
        active = (
            MentorApplication.objects
            .select_for_update()
            .filter(user=user, status__in=MentorApplication.ACTIVE_STATUSES)
            .first()
        )
        if active and active.status != MentorApplication.Status.DRAFT:
            raise MentorApplicationError(
                f"You already have a {active.status} application."
            )

        app = active or MentorApplication(user=user)
        if mentor_kyc is not None:
            app.mentor_kyc = mentor_kyc
        app.status = MentorApplication.Status.SUBMITTED
        app.submitted_at = timezone.now()
        app.save()

        _audit(app, actor=user, action=MentorApplicationAudit.Action.SUBMITTED)
    return app


def approve(*, actor, application_id, note: str = "") -> MentorApplication:
    """Approve a submitted application — flips the target user to EAGLE."""
    with transaction.atomic():
        app = MentorApplication.objects.select_for_update().get(pk=application_id)

        if app.status != MentorApplication.Status.SUBMITTED:
            raise MentorApplicationError(
                f"Application is not submitted (status={app.status})."
            )
        if app.user_id == actor.id:
            raise MentorApplicationError("You cannot approve your own application.")

        app.status = MentorApplication.Status.APPROVED
        app.reviewed_by = actor
        app.reviewed_at = timezone.now()
        app.review_notes = (note or "").strip()[:2000]
        app.save(update_fields=[
            "status", "reviewed_by", "reviewed_at", "review_notes", "updated_at",
        ])

        # Stacked-mentor activation (flip-role). Mentee level/program rows live in
        # the nests app and are intentionally left untouched.
        target = app.user
        if target.role != User.Role.EAGLE:
            target.role = User.Role.EAGLE
            target.save(update_fields=["role", "updated_at"])

        _audit(
            app, actor=actor,
            action=MentorApplicationAudit.Action.APPROVED,
            reason=app.review_notes,
        )

    # Email sent OUTSIDE the transaction so a transport failure can't roll back
    # the role flip. _send_themed_email is fail_silently=True at the Django layer
    # AND wrapped in try/except — never propagates.
    _notify_decision(app, approved=True)
    return app


def reject(*, actor, application_id, reason: str) -> MentorApplication:
    reason = (reason or "").strip()
    if len(reason) < 10:
        raise MentorApplicationError("Rejection reason must be at least 10 characters.")

    with transaction.atomic():
        app = MentorApplication.objects.select_for_update().get(pk=application_id)
        if app.status != MentorApplication.Status.SUBMITTED:
            raise MentorApplicationError(
                f"Application is not submitted (status={app.status})."
            )

        app.status = MentorApplication.Status.REJECTED
        app.reviewed_by = actor
        app.reviewed_at = timezone.now()
        app.rejection_reason = reason[:2000]
        app.save(update_fields=[
            "status", "reviewed_by", "reviewed_at", "rejection_reason", "updated_at",
        ])

        _audit(
            app, actor=actor,
            action=MentorApplicationAudit.Action.REJECTED,
            reason=reason,
        )

    _notify_decision(app, approved=False)
    return app


def withdraw(*, user, application_id) -> MentorApplication:
    """Applicant withdraws their own pending (draft/submitted) application."""
    with transaction.atomic():
        app = MentorApplication.objects.select_for_update().get(pk=application_id)
        if app.user_id != user.id:
            raise MentorApplicationError("You can only withdraw your own application.")
        if app.status not in (
            MentorApplication.Status.DRAFT,
            MentorApplication.Status.SUBMITTED,
        ):
            raise MentorApplicationError(
                f"Cannot withdraw a {app.status} application."
            )

        app.status = MentorApplication.Status.WITHDRAWN
        app.save(update_fields=["status", "updated_at"])

        _audit(app, actor=user, action=MentorApplicationAudit.Action.WITHDRAWN)
    return app

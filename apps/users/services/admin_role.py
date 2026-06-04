"""
Admin role management service (plan 18-01).

All grant / revoke flows go through this module so the audit log, signals,
and emails fire in one place. Views are kept thin — they validate input,
delegate here, and return the result.

Errors raised by this module are HTTP-mappable:
  * ``LastAdminError`` -> 409 ``last_admin``
  * ``PendingReviewError`` -> 409 ``pending_review_work`` with payload
  * ``IneligibleError`` -> 403 ``ineligible``
  * ``AlreadyAdminError`` -> 409 ``already_admin``
  * ``InviteError`` -> 410 / 403 depending on .code
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from ..models_admin import (
    AdminInvite,
    AdminRoleAudit,
    AdminRoleRequest,
    _generate_invite_token,
    hash_invite_token,
)

logger = logging.getLogger(__name__)
User = get_user_model()


# ─── Errors ──────────────────────────────────────────────────────────────────

class AdminRoleError(Exception):
    """Base for all admin-role flow errors."""
    code: str = "admin_role_error"


class LastAdminError(AdminRoleError):
    code = "last_admin"


class PendingReviewError(AdminRoleError):
    code = "pending_review_work"

    def __init__(self, review_ids: list[str]):
        super().__init__("Reassign pending reviews before revoking admin.")
        self.review_ids = review_ids


class IneligibleError(AdminRoleError):
    code = "ineligible"

    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons) or "Not eligible.")
        self.reasons = reasons


class AlreadyAdminError(AdminRoleError):
    code = "already_admin"


class InviteError(AdminRoleError):
    def __init__(self, message: str, code: str = "invite_error"):
        super().__init__(message)
        self.code = code


# ─── Helpers ─────────────────────────────────────────────────────────────────

FIRST_ADMIN_SESSION_TTL = 60 * 60 * 24  # 24h


def first_admin_session_key(user_id) -> str:
    return f"first_admin_session:{user_id}"


def _admin_pool_count(exclude_user_id=None) -> int:
    qs = User.objects.filter(is_platform_staff=True, is_active=True)
    if exclude_user_id:
        qs = qs.exclude(pk=exclude_user_id)
    return qs.count()


def _pending_kyc_reviews_for(user) -> list[str]:
    """
    Return a list of MentorKYC/MenteeKYC primary keys that ``user`` is
    currently assigned to review. Used as a guard before revoking admin.

    The KYC review system today doesn't track an explicit assignee — it's
    open-pool. So this returns an empty list until that ownership concept
    exists. The hook is here so the FE can prompt reassignment as soon as
    assignment lands.
    """
    return []


# ─── Eligibility ─────────────────────────────────────────────────────────────

def get_eligibility(user) -> dict:
    """Wrapper around User.can_request_admin() for service-layer parity."""
    return user.can_request_admin()


# ─── EOI flow ────────────────────────────────────────────────────────────────

@dataclass
class EOIResult:
    request: AdminRoleRequest
    eligible: bool


def submit_eoi(user, reason: str) -> AdminRoleRequest:
    """Create a new pending EOI for ``user`` after re-checking eligibility."""
    elig = user.can_request_admin()
    if not elig["eligible"]:
        raise IneligibleError(elig["reasons"])

    reason = (reason or "").strip()
    if len(reason) < 50:
        raise IneligibleError(["Reason must be at least 50 characters."])

    with transaction.atomic():
        req = AdminRoleRequest.objects.create(
            user=user,
            reason=reason,
            status=AdminRoleRequest.Status.PENDING,
        )

    _notify_admins_new_eoi(req)
    return req


def withdraw_eoi(user) -> AdminRoleRequest:
    """User cancels their own pending EOI. Idempotent: returns 404 upstream."""
    try:
        req = AdminRoleRequest.objects.get(
            user=user,
            status=AdminRoleRequest.Status.PENDING,
        )
    except AdminRoleRequest.DoesNotExist as e:
        raise AdminRoleError("No pending request to withdraw.") from e

    req.status = AdminRoleRequest.Status.WITHDRAWN
    req.decided_at = timezone.now()
    req.save(update_fields=["status", "decided_at", "updated_at"])
    return req


def approve_eoi(*, actor, request_id, note: str = "") -> AdminRoleRequest:
    """Approve an EOI — promotes the target user."""
    with transaction.atomic():
        req = AdminRoleRequest.objects.select_for_update().get(pk=request_id)

        if req.status != AdminRoleRequest.Status.PENDING:
            raise AdminRoleError(f"Request is not pending (status={req.status}).")
        if req.user_id == actor.id:
            raise AdminRoleError("You cannot approve your own request.")
        if req.user.is_platform_staff:
            raise AlreadyAdminError("Target user already has admin privileges.")

        req.status = AdminRoleRequest.Status.APPROVED
        req.decided_by = actor
        req.decided_at = timezone.now()
        req.decision_note = (note or "").strip()[:1000]
        req.save(update_fields=[
            "status", "decided_by", "decided_at", "decision_note", "updated_at",
        ])

        _grant_admin(
            target=req.user,
            actor=actor,
            source=AdminRoleAudit.Source.EOI,
            reason=req.decision_note,
        )

    _notify_eoi_decision(req, approved=True)
    return req


def reject_eoi(*, actor, request_id, note: str) -> AdminRoleRequest:
    note = (note or "").strip()
    if len(note) < 10:
        raise AdminRoleError("Rejection note must be at least 10 characters.")

    with transaction.atomic():
        req = AdminRoleRequest.objects.select_for_update().get(pk=request_id)
        if req.status != AdminRoleRequest.Status.PENDING:
            raise AdminRoleError(f"Request is not pending (status={req.status}).")

        req.status = AdminRoleRequest.Status.REJECTED
        req.decided_by = actor
        req.decided_at = timezone.now()
        req.decision_note = note[:1000]
        req.save(update_fields=[
            "status", "decided_by", "decided_at", "decision_note", "updated_at",
        ])

    _notify_eoi_decision(req, approved=False)
    return req


# ─── Invite flow ─────────────────────────────────────────────────────────────

def send_invite(*, actor, email: str, message: str = "") -> tuple[AdminInvite, str]:
    """Create a hashed-token invite.

    Returns ``(invite, raw_token)``. The raw token MUST go into the email
    link and may be shown ONCE to the admin who issued it. It is never
    stored in the DB — only its SHA-256 hash.
    """
    email = (email or "").strip().lower()
    if not email:
        raise InviteError("Email is required.", code="email_required")

    has_pending = AdminInvite.objects.filter(
        email=email,
        status=AdminInvite.Status.SENT,
    ).exists()
    if has_pending:
        raise InviteError(
            "An active invite already exists for this email.",
            code="invite_exists",
        )

    raw_token = _generate_invite_token()
    invite = AdminInvite.objects.create(
        email=email,
        invited_by=actor,
        token_hash=hash_invite_token(raw_token),
        message=message[:500] if message else "",
    )
    _notify_invite_sent(invite, raw_token=raw_token)
    return invite, raw_token


def revoke_invite(*, actor, invite_id) -> AdminInvite:
    invite = AdminInvite.objects.get(pk=invite_id)
    if invite.status != AdminInvite.Status.SENT:
        raise InviteError(
            f"Invite is not active (status={invite.status}).",
            code="not_active",
        )
    invite.status = AdminInvite.Status.REVOKED
    invite.save(update_fields=["status", "updated_at"])
    return invite


def accept_invite(*, user, token: str) -> AdminInvite:
    """
    User accepts an invite. Generic errors on failure (no enumeration).

    Looks up by SHA-256 hash of the supplied raw token. Storing only the
    hash means a DB read can't be used to enumerate or replay grants.
    """
    expired = False
    token_hash = hash_invite_token(token or "")
    with transaction.atomic():
        try:
            invite = AdminInvite.objects.select_for_update().get(token_hash=token_hash)
        except AdminInvite.DoesNotExist as e:
            raise InviteError("Invite is invalid or has expired.", code="invalid") from e

        if invite.status != AdminInvite.Status.SENT:
            raise InviteError("Invite is invalid or has expired.", code="invalid")

        if invite.is_expired:
            invite.status = AdminInvite.Status.EXPIRED
            invite.save(update_fields=["status", "updated_at"])
            expired = True
        else:
            if user.email.lower() != invite.email.lower():
                # No state change yet — raising here is a safe rollback.
                raise InviteError(
                    "This invite was sent to a different email address.",
                    code="email_mismatch",
                )
            if user.is_platform_staff:
                raise AlreadyAdminError("You already have admin privileges.")

            invite.status = AdminInvite.Status.ACCEPTED
            invite.accepted_by = user
            invite.accepted_at = timezone.now()
            invite.save(update_fields=[
                "status", "accepted_by", "accepted_at", "updated_at",
            ])
            _grant_admin(
                target=user,
                actor=invite.invited_by,
                source=AdminRoleAudit.Source.INVITE,
                reason=f"Accepted invite from {invite.invited_by.email if invite.invited_by else 'system'}.",
            )

    # Commit-then-raise: the EXPIRED save above must persist, so we raise
    # only after the atomic block has closed cleanly.
    if expired:
        raise InviteError("Invite is invalid or has expired.", code="invalid")

    return invite


# ─── Revocation ──────────────────────────────────────────────────────────────

def revoke_admin(*, actor, target_id, reason: str) -> User:
    """Admin demotes another admin. Body requires reason."""
    reason = (reason or "").strip()
    if len(reason) < 10:
        raise AdminRoleError("Reason must be at least 10 characters.")

    target = User.objects.get(pk=target_id)
    if target.id == actor.id:
        raise AdminRoleError("Use the self-revoke endpoint to revoke your own admin.")
    if not target.is_platform_staff:
        raise AdminRoleError("Target is not an admin.")

    if _admin_pool_count(exclude_user_id=target.id) < 1:
        raise LastAdminError("Cannot revoke — the platform would have no admins.")

    pending = _pending_kyc_reviews_for(target)
    if pending:
        raise PendingReviewError(pending)

    return _revoke_admin(
        target=target,
        actor=actor,
        action=AdminRoleAudit.Action.REVOKED,
        source=AdminRoleAudit.Source.MANUAL,
        reason=reason[:2000],
    )


def self_revoke_admin(*, user, reason: str = "") -> User:
    if not user.is_platform_staff:
        raise AdminRoleError("You do not hold admin privileges.")
    if _admin_pool_count(exclude_user_id=user.id) < 1:
        raise LastAdminError("Cannot revoke — you are the only admin.")
    return _revoke_admin(
        target=user,
        actor=user,
        action=AdminRoleAudit.Action.SELF_REVOKED,
        source=AdminRoleAudit.Source.MANUAL,
        reason=(reason or "").strip()[:2000],
    )


# ─── Internals ───────────────────────────────────────────────────────────────

def _grant_admin(*, target, actor, source, reason: str) -> None:
    """
    Promote ``target`` and write the audit row. Idempotent on the User
    fields; AlreadyAdminError caller-side prevents duplicate audit entries.
    """
    if not target.is_platform_staff:
        target.is_platform_staff = True
        # is_staff = True so the user can also access Django admin if needed.
        # Existing pure admins already have it set, so this is a no-op for them.
        if not target.is_staff:
            target.is_staff = True
            target.save(update_fields=["is_platform_staff", "is_staff", "updated_at"])
        else:
            target.save(update_fields=["is_platform_staff", "updated_at"])

    AdminRoleAudit.objects.create(
        actor=actor,
        target=target,
        action=AdminRoleAudit.Action.GRANTED,
        source=source,
        reason=reason or "",
    )

    # FE reads this flag from /auth/me/ to land in admin mode on the next session.
    cache.set(first_admin_session_key(target.id), True, FIRST_ADMIN_SESSION_TTL)

    _notify_promoted(target=target)


def _revoke_admin(*, target, actor, action, source, reason: str) -> User:
    """Drop privileges and write audit. Keeps mentor identity intact."""
    target.is_platform_staff = False
    # Preserve is_staff so they can still access any per-app Django admin
    # surfaces tied to their content authorship. Pure-admin (role='admin')
    # users keep their role; mentor stacks lose only the platform flag.
    target.save(update_fields=["is_platform_staff", "updated_at"])

    AdminRoleAudit.objects.create(
        actor=actor,
        target=target,
        action=action,
        source=source,
        reason=reason or "",
    )

    cache.delete(first_admin_session_key(target.id))
    _notify_demoted(target=target, actor=actor)
    return target


# ─── Notifications ───────────────────────────────────────────────────────────
# All admin-role emails use the shared themed templates under templates/emails/.
# Failures are logged but never block the flow — the audit row is the source
# of truth.

def _frontend_url() -> str:
    """Absolute FE base URL for clickable links in emails."""
    return getattr(settings, "FRONTEND_URL", "http://localhost:5173").rstrip("/")


def _support_email() -> str:
    return (
        getattr(settings, "SUPPORT_EMAIL", None)
        or getattr(settings, "DEFAULT_FROM_EMAIL", "support@eaglesneaglets.com")
    )


def _send_themed_email(
    *,
    subject: str,
    template: str,
    context: dict,
    recipients: list[str],
) -> None:
    """Render a themed HTML email and send. Failures never raise."""
    if not recipients:
        return
    try:
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.utils.html import strip_tags

        ctx = {
            "support_email": _support_email(),
            "frontend_url": _frontend_url(),
            **context,
        }
        html_message = render_to_string(template, ctx)
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
        logger.warning("admin-role email send failed: %s", e)


def _all_admin_emails(exclude_id=None) -> list[str]:
    qs = User.objects.filter(is_platform_staff=True, is_active=True)
    if exclude_id:
        qs = qs.exclude(pk=exclude_id)
    return list(qs.values_list("email", flat=True))


def _notify_admins_new_eoi(req: AdminRoleRequest) -> None:
    _send_themed_email(
        subject=f"New admin role request: {req.user.full_name}",
        template="emails/admin_role_eoi_submitted.html",
        context={
            "requester_name": req.user.full_name,
            "requester_email": req.user.email,
            "reason": req.reason,
            "review_url": f"{_frontend_url()}/admin/team",
        },
        recipients=_all_admin_emails(),
    )


def _notify_eoi_decision(req: AdminRoleRequest, *, approved: bool) -> None:
    if approved:
        _send_themed_email(
            subject="You're now an admin on Eagles & Eaglets",
            template="emails/admin_role_eoi_approved.html",
            context={
                "first_name": req.user.first_name,
                "note": req.decision_note,
                "dashboard_url": f"{_frontend_url()}/admin/dashboard",
                "guidelines_url": f"{_frontend_url()}/admin/team",
            },
            recipients=[req.user.email],
        )
    else:
        _send_themed_email(
            subject="Update on your admin role request",
            template="emails/admin_role_eoi_rejected.html",
            context={
                "first_name": req.user.first_name,
                "note": req.decision_note,
                "settings_url": f"{_frontend_url()}/settings/account",
            },
            recipients=[req.user.email],
        )


def _notify_invite_sent(invite: AdminInvite, *, raw_token: str) -> None:
    """raw_token is passed in because the DB no longer stores plaintext."""
    _send_themed_email(
        subject="You're invited to administrate Eagles & Eaglets",
        template="emails/admin_role_invite.html",
        context={
            "inviter_name": invite.invited_by.full_name if invite.invited_by else None,
            "accept_url": f"{_frontend_url()}/admin-role/accept/{raw_token}",
            "personal_message": invite.message,
            "expires_at": invite.expires_at,
        },
        recipients=[invite.email],
    )


def _notify_promoted(*, target: User) -> None:
    pass  # decision email above already covers EOI path; invite acceptance is implicit.


def _notify_demoted(*, target: User, actor: Optional[User]) -> None:
    actor_name = actor.full_name if (actor and actor.id != target.id) else None

    # 1. Email to the demoted user.
    _send_themed_email(
        subject="Your admin role has been revoked",
        template="emails/admin_role_demoted.html",
        context={
            "first_name": target.first_name,
            "actor_name": actor_name,
            "reason": "",  # explicit reason flows through audit log — not duplicated here
            "dashboard_url": f"{_frontend_url()}/dashboard",
        },
        recipients=[target.email],
    )

    # 2. Email to remaining admins.
    remaining_count = _admin_pool_count()
    _send_themed_email(
        subject=f"Admin team update: {target.full_name} removed",
        template="emails/admin_role_team_demoted.html",
        context={
            "demoted_name": target.full_name,
            "demoted_email": target.email,
            "remaining_count": remaining_count,
            "team_url": f"{_frontend_url()}/admin/team",
        },
        recipients=_all_admin_emails(exclude_id=target.id),
    )

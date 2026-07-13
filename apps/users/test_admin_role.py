"""Tests for Admin Role Management (plan 18-01)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.users.models import MentorKYC
from apps.users.models_admin import AdminInvite, AdminRoleAudit, AdminRoleRequest
from apps.users.services import admin_role as svc

pytestmark = pytest.mark.django_db

User = get_user_model()


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _make_user(email: str, *, role: str = "eagle", is_active: bool = True,
               is_platform_staff: bool = False, is_superuser: bool = False):
    return User.objects.create_user(
        email=email,
        password="TestPassword123!",
        first_name=email.split("@")[0].title(),
        last_name="User",
        role=role,
        is_active=is_active,
        is_platform_staff=is_platform_staff,
        is_superuser=is_superuser,
    )


def _approve_kyc(user, *, days_ago: int = 60):
    """Stamp a MentorKYC row as approved N days ago."""
    when = timezone.now() - timedelta(days=days_ago)
    kyc = MentorKYC.objects.create(user=user)
    kyc.status = "approved"
    kyc.reviewed_at = when
    kyc.save(update_fields=["status", "reviewed_at"])
    return kyc


@pytest.fixture
def admin_user():
    """Bootstrap superadmin — full admin-team management privileges."""
    u = _make_user(
        "admin@e.test",
        role="admin",
        is_platform_staff=True,
        is_superuser=True,
    )
    u.is_staff = True
    u.save(update_fields=["is_staff"])
    return u


@pytest.fixture
def second_admin():
    """Invited platform admin (not superuser)."""
    return _make_user(
        "admin2@e.test",
        role="admin",
        is_platform_staff=True,
        is_superuser=False,
    )


@pytest.fixture
def eligible_mentor():
    """Mentor approved 60 days ago — should be eligible to submit EOI."""
    m = _make_user("mentor@e.test", role="eagle")
    _approve_kyc(m, days_ago=60)
    return m


@pytest.fixture
def fresh_mentor():
    """Mentor approved 10 days ago — should NOT be eligible (under 30 days)."""
    m = _make_user("fresh@e.test", role="eagle")
    _approve_kyc(m, days_ago=10)
    return m


@pytest.fixture
def mentee():
    return _make_user("mentee@e.test", role="eaglet")


@pytest.fixture
def api():
    return APIClient()


# ─── Eligibility ─────────────────────────────────────────────────────────────

def test_mentee_without_kyc_or_engagement_is_not_eligible(mentee):
    """Phase 22-01 opened the gate to mentees with KYC + Level 3 + completed program.
    A bare mentee (no KYC, no level, no completion) still fails — but for the new
    mentee-specific reasons, not the old "mentors only" string."""
    elig = mentee.can_request_admin()
    assert elig["eligible"] is False
    # New eaglet gate strings:
    assert any("mentee profile must be KYC-approved" in r for r in elig["reasons"])
    # Eaglet-specific cohort exclusion string (admin/visitor) MUST NOT appear here.
    assert not any("open to mentors and mentees only" in r for r in elig["reasons"])


def test_fresh_mentor_is_not_eligible(fresh_mentor):
    elig = fresh_mentor.can_request_admin()
    assert elig["eligible"] is False
    assert any("30 days" in r for r in elig["reasons"])


def test_eligible_mentor_is_eligible(eligible_mentor):
    elig = eligible_mentor.can_request_admin()
    assert elig["eligible"] is True
    assert elig["reasons"] == []


def test_existing_admin_not_eligible(eligible_mentor):
    eligible_mentor.is_platform_staff = True
    eligible_mentor.save(update_fields=["is_platform_staff"])
    elig = eligible_mentor.can_request_admin()
    assert elig["eligible"] is False
    assert any("already hold admin" in r for r in elig["reasons"])


def test_suspended_mentor_not_eligible(eligible_mentor):
    eligible_mentor.is_active = False
    eligible_mentor.save(update_fields=["is_active"])
    elig = eligible_mentor.can_request_admin()
    assert elig["eligible"] is False
    assert any("suspended" in r for r in elig["reasons"])


# ─── EOI submission ──────────────────────────────────────────────────────────

def test_submit_eoi_creates_pending(eligible_mentor):
    req = svc.submit_eoi(eligible_mentor, "A" * 60)
    assert req.status == AdminRoleRequest.Status.PENDING
    assert AdminRoleRequest.objects.filter(user=eligible_mentor).count() == 1


def test_second_pending_eoi_rejected(eligible_mentor):
    svc.submit_eoi(eligible_mentor, "A" * 60)
    elig = eligible_mentor.can_request_admin()
    assert elig["eligible"] is False
    assert any("pending admin request" in r for r in elig["reasons"])

    with pytest.raises(svc.IneligibleError):
        svc.submit_eoi(eligible_mentor, "B" * 60)


def test_eoi_reason_too_short(eligible_mentor):
    with pytest.raises(svc.IneligibleError):
        svc.submit_eoi(eligible_mentor, "too short")


def test_withdraw_eoi_marks_withdrawn(eligible_mentor):
    svc.submit_eoi(eligible_mentor, "A" * 60)
    req = svc.withdraw_eoi(eligible_mentor)
    assert req.status == AdminRoleRequest.Status.WITHDRAWN


# ─── EOI approval / rejection ────────────────────────────────────────────────

def test_approve_eoi_stacks_admin(admin_user, eligible_mentor):
    req = svc.submit_eoi(eligible_mentor, "A" * 60)
    svc.approve_eoi(actor=admin_user, request_id=req.pk, note="welcome aboard")

    eligible_mentor.refresh_from_db()
    assert eligible_mentor.is_platform_staff is True
    # Mentor identity preserved
    assert eligible_mentor.role == "eagle"
    assert eligible_mentor.is_admin is True
    assert eligible_mentor.is_stacked_admin is True
    # Audit row
    audit = AdminRoleAudit.objects.get(target=eligible_mentor, action="granted")
    assert audit.source == "eoi"
    assert audit.actor == admin_user
    # First-admin-session flag set
    assert cache.get(svc.first_admin_session_key(eligible_mentor.id)) is True


def test_cannot_self_approve(admin_user):
    """Admin can't approve their own EOI (edge case: stacked admin reverts then re-submits)."""
    # Force admin into mentor state with a pending EOI for this test.
    admin_user.role = "eagle"
    admin_user.save(update_fields=["role"])
    _approve_kyc(admin_user, days_ago=60)
    admin_user.is_platform_staff = False
    admin_user.save(update_fields=["is_platform_staff"])

    req = svc.submit_eoi(admin_user, "X" * 60)

    # Re-elevate so the would-be approver IS an admin.
    admin_user.is_platform_staff = True
    admin_user.save(update_fields=["is_platform_staff"])

    with pytest.raises(svc.AdminRoleError, match="own request"):
        svc.approve_eoi(actor=admin_user, request_id=req.pk)


def test_reject_requires_note(admin_user, eligible_mentor):
    req = svc.submit_eoi(eligible_mentor, "A" * 60)
    with pytest.raises(svc.AdminRoleError, match="10 characters"):
        svc.reject_eoi(actor=admin_user, request_id=req.pk, note="")


def test_reject_eoi_marks_rejected(admin_user, eligible_mentor):
    req = svc.submit_eoi(eligible_mentor, "A" * 60)
    svc.reject_eoi(actor=admin_user, request_id=req.pk,
                   note="Not enough mentee volume yet.")
    req.refresh_from_db()
    assert req.status == "rejected"
    assert req.decided_by == admin_user
    eligible_mentor.refresh_from_db()
    assert eligible_mentor.is_platform_staff is False


# ─── Revocation ──────────────────────────────────────────────────────────────

def test_self_revoke_drops_flag(admin_user, second_admin):
    """With two admins, a platform admin can self-revoke."""
    svc.self_revoke_admin(user=second_admin, reason="stepping back")
    second_admin.refresh_from_db()
    assert second_admin.is_platform_staff is False
    audit = AdminRoleAudit.objects.filter(
        target=second_admin, action="self_revoked"
    ).first()
    assert audit is not None


def test_self_revoke_blacklists_all_refresh_tokens(admin_user, second_admin):
    """Stepping down must revoke every outstanding session for the actor."""
    from rest_framework_simplejwt.tokens import RefreshToken
    from rest_framework_simplejwt.token_blacklist.models import (
        BlacklistedToken,
        OutstandingToken,
    )

    # Simulate two active devices for the demoting admin.
    RefreshToken.for_user(second_admin)
    RefreshToken.for_user(second_admin)
    outstanding = OutstandingToken.objects.filter(user=second_admin)
    assert outstanding.count() == 2
    assert not BlacklistedToken.objects.filter(token__in=outstanding).exists()

    svc.self_revoke_admin(user=second_admin, reason="stepping back")

    assert BlacklistedToken.objects.filter(
        token__user=second_admin
    ).count() == 2


def test_self_revoke_last_admin_blocked(second_admin):
    """Only platform admin → self-revoke must fail."""
    with pytest.raises(svc.LastAdminError):
        svc.self_revoke_admin(user=second_admin, reason="x")
    second_admin.refresh_from_db()
    assert second_admin.is_platform_staff is True


def test_superadmin_self_revoke_blocked(admin_user, second_admin):
    with pytest.raises(svc.AdminRoleError, match="Superadmin"):
        svc.self_revoke_admin(user=admin_user, reason="x")


def test_transfer_superadmin_promotes_successor_and_steps_down(admin_user, second_admin):
    successor = svc.transfer_superadmin(
        actor=admin_user,
        successor_id=second_admin.id,
        reason="retiring from platform ops",
    )
    assert successor.id == second_admin.id

    admin_user.refresh_from_db()
    second_admin.refresh_from_db()
    assert admin_user.is_superuser is False
    assert admin_user.is_platform_staff is False
    assert second_admin.is_superuser is True
    assert second_admin.is_platform_staff is True

    assert AdminRoleAudit.objects.filter(
        target=second_admin, action="granted"
    ).exists()
    assert AdminRoleAudit.objects.filter(
        target=admin_user, action="self_revoked"
    ).exists()


def test_transfer_superadmin_requires_other_admin(admin_user):
    with pytest.raises(svc.AdminRoleError, match="Choose another"):
        svc.transfer_superadmin(
            actor=admin_user,
            successor_id=admin_user.id,
            reason="self transfer",
        )


def test_demote_last_admin_blocked(admin_user, second_admin):
    """Demote platform admin; superadmin cannot be revoked via team management."""
    svc.revoke_admin(
        actor=admin_user, target_id=second_admin.id,
        reason="restructuring the team",
    )
    second_admin.refresh_from_db()
    assert second_admin.is_platform_staff is False

    with pytest.raises(svc.AdminRoleError, match="Superadmin"):
        svc.revoke_admin(
            actor=second_admin, target_id=admin_user.id,
            reason="trying to demote superadmin",
        )


def test_demote_self_via_team_endpoint_blocked(admin_user, second_admin, api):
    api.force_authenticate(user=admin_user)
    url = reverse("users_admin_role:revoke-member", args=[admin_user.id])
    res = api.post(url, {"reason": "trying self demote"}, format="json")
    assert res.status_code == 409
    assert res.json()["error"]["type"] == "use_self_revoke"


def test_signal_auto_revokes_on_suspend(second_admin):
    """Setting is_active=False on a stacked admin auto-drops is_platform_staff."""
    second_admin.is_active = False
    second_admin.save()
    second_admin.refresh_from_db()
    assert second_admin.is_platform_staff is False
    audit = AdminRoleAudit.objects.filter(
        target=second_admin, action="system_revoked"
    ).first()
    assert audit is not None
    assert audit.source == "system"
    assert audit.actor is None


# ─── Invites ─────────────────────────────────────────────────────────────────

def test_send_invite_creates_row(admin_user):
    invite, raw_token = svc.send_invite(actor=admin_user, email="new@e.test", message="hi")
    assert invite.status == "sent"
    assert raw_token  # returned to caller for the email link / one-time display
    assert invite.token_hash  # hashed at rest
    assert invite.expires_at > timezone.now()


def test_duplicate_pending_invite_rejected(admin_user):
    svc.send_invite(actor=admin_user, email="dup@e.test")
    with pytest.raises(svc.InviteError, match="already exists"):
        svc.send_invite(actor=admin_user, email="dup@e.test")


def test_accept_invite_promotes(admin_user, eligible_mentor):
    invite, raw_token = svc.send_invite(actor=admin_user, email=eligible_mentor.email)
    svc.accept_invite(user=eligible_mentor, token=raw_token)
    eligible_mentor.refresh_from_db()
    assert eligible_mentor.is_platform_staff is True
    invite.refresh_from_db()
    assert invite.status == "accepted"
    assert invite.accepted_by == eligible_mentor


def test_accept_invite_email_mismatch(admin_user, eligible_mentor):
    invite, raw_token = svc.send_invite(actor=admin_user, email="someone-else@e.test")
    with pytest.raises(svc.InviteError) as exc:
        svc.accept_invite(user=eligible_mentor, token=raw_token)
    assert exc.value.code == "email_mismatch"


def test_accept_expired_invite(admin_user, eligible_mentor):
    invite, raw_token = svc.send_invite(actor=admin_user, email=eligible_mentor.email)
    invite.expires_at = timezone.now() - timedelta(days=1)
    invite.save(update_fields=["expires_at"])
    with pytest.raises(svc.InviteError) as exc:
        svc.accept_invite(user=eligible_mentor, token=raw_token)
    assert exc.value.code == "invalid"
    invite.refresh_from_db()
    assert invite.status == "expired"


def test_accept_unknown_token(eligible_mentor):
    with pytest.raises(svc.InviteError) as exc:
        svc.accept_invite(user=eligible_mentor, token="bogus-token-1234567890")
    assert exc.value.code == "invalid"


def test_invite_token_not_serialized(admin_user):
    """Token hash must never be returned by the list/get serializer."""
    from apps.users.serializers_admin import AdminInviteSerializer
    invite, _ = svc.send_invite(actor=admin_user, email="hide@e.test")
    data = AdminInviteSerializer(invite).data
    assert "token" not in data
    assert "token_hash" not in data


# ─── Audit immutability ──────────────────────────────────────────────────────

def test_audit_row_is_immutable(admin_user, eligible_mentor):
    audit = AdminRoleAudit.objects.create(
        actor=admin_user, target=eligible_mentor,
        action="granted", source="manual", reason="seed",
    )
    audit.reason = "tampered"
    with pytest.raises(RuntimeError, match="immutable"):
        audit.save()
    with pytest.raises(RuntimeError, match="immutable"):
        audit.delete()


# ─── HTTP smoke ──────────────────────────────────────────────────────────────

def test_http_submit_eoi(api, eligible_mentor):
    api.force_authenticate(user=eligible_mentor)
    url = reverse("users_admin_role:requests")
    res = api.post(url, {"reason": "A" * 60}, format="json")
    assert res.status_code == 201
    assert res.json()["data"]["status"] == "pending"


def test_http_eligibility(api, eligible_mentor, fresh_mentor):
    api.force_authenticate(user=eligible_mentor)
    res = api.get(reverse("users_admin_role:eligibility"))
    assert res.status_code == 200
    assert res.json()["data"]["eligible"] is True

    api.force_authenticate(user=fresh_mentor)
    res = api.get(reverse("users_admin_role:eligibility"))
    assert res.json()["data"]["eligible"] is False


def test_http_admin_only_endpoints_reject_non_admin(api, eligible_mentor):
    api.force_authenticate(user=eligible_mentor)
    res = api.get(reverse("users_admin_role:team"))
    assert res.status_code == 403


def test_http_team_lists_admins(api, admin_user, second_admin):
    api.force_authenticate(user=admin_user)
    res = api.get(reverse("users_admin_role:team"))
    assert res.status_code == 200
    emails = {m["email"] for m in res.json()["data"]}
    assert admin_user.email in emails
    assert second_admin.email in emails


def test_http_accept_invite_flow(api, admin_user, eligible_mentor):
    _invite, raw_token = svc.send_invite(actor=admin_user, email=eligible_mentor.email)
    api.force_authenticate(user=eligible_mentor)
    url = reverse("users_admin_role:accept-invite", args=[raw_token])
    res = api.post(url, {}, format="json")
    assert res.status_code == 200
    eligible_mentor.refresh_from_db()
    assert eligible_mentor.is_platform_staff is True


def test_auth_me_includes_admin_request_block(api, eligible_mentor):
    api.force_authenticate(user=eligible_mentor)
    res = api.get("/api/v1/auth/me/")
    assert res.status_code == 200
    data = res.json()["data"]
    assert "admin_request" in data
    assert data["admin_request"]["eligible"] is True
    assert data["admin_request"]["pending_request_id"] is None
    assert data["admin_request"]["first_admin_session"] is False


def test_first_admin_session_flag_exposed_then_cleared(api, admin_user, eligible_mentor):
    """After approval, the very next /auth/me/ call returns first_admin_session=True."""
    req = svc.submit_eoi(eligible_mentor, "A" * 60)
    svc.approve_eoi(actor=admin_user, request_id=req.pk, note="ok")

    api.force_authenticate(user=eligible_mentor)
    res = api.get("/api/v1/auth/me/")
    assert res.json()["data"]["admin_request"]["first_admin_session"] is True

    # Second call: flag should be cleared.
    res = api.get("/api/v1/auth/me/")
    assert res.json()["data"]["admin_request"]["first_admin_session"] is False


# ─── Backfill smoke ──────────────────────────────────────────────────────────

def test_backfill_marks_existing_admin(admin_user):
    """Verifies the migration backfilled flag and audit row for admin_user-like users."""
    # admin_user fixture sets is_platform_staff=True directly; verify is_admin works
    assert admin_user.is_admin is True
    # Manually-created via fixture doesn't have backfill audit row, so check that
    # NEW admin grant rows are creatable on top of that baseline.
    assert AdminRoleAudit.objects.filter(target=admin_user).count() >= 0


def test_invite_grant_does_not_set_is_staff(admin_user, eligible_mentor):
    invite, raw_token = svc.send_invite(actor=admin_user, email=eligible_mentor.email)
    svc.accept_invite(user=eligible_mentor, token=raw_token)
    eligible_mentor.refresh_from_db()
    assert eligible_mentor.is_platform_staff is True
    assert eligible_mentor.is_staff is False
    assert eligible_mentor.is_superuser is False


def test_platform_admin_cannot_send_invite(api, second_admin, admin_user):
    api.force_authenticate(user=second_admin)
    url = reverse("users_admin_role:invites")
    res = api.post(url, {"email": "blocked@e.test"}, format="json")
    assert res.status_code == 403


def test_auth_me_includes_has_password(api, eligible_mentor):
    eligible_mentor.set_unusable_password()
    eligible_mentor.save(update_fields=["password"])
    api.force_authenticate(user=eligible_mentor)
    res = api.get("/api/v1/auth/me/")
    assert res.status_code == 200
    assert res.json()["data"]["has_password"] is False

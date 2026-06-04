"""Tests for User.can_request_admin role branching (plan 22-01).

Strategy: stub the external dependencies (MenteeKYC, MentorKYC, compute_level,
ProgramEnrollment) via monkeypatch so we don't construct rows for every test —
the contract under test is the eligibility branching, not the data layer.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

pytestmark = pytest.mark.django_db

User = get_user_model()


def _make_user(email, *, role):
    return User.objects.create_user(
        email=email,
        password="TestPassword123!",
        first_name=email.split("@")[0].title(),
        last_name="User",
        role=role,
    )


def _stub_mentee_kyc(user, *, status="approved", days_ago=10):
    """Inject a mentee_kyc-like stub via Django's fields_cache to bypass the
    OneToOne descriptor's type validation. can_request_admin reads .status and
    .reviewed_at — SimpleNamespace satisfies the contract."""
    stub = SimpleNamespace(
        status=status,
        reviewed_at=timezone.now() - timedelta(days=days_ago) if status == "approved" else None,
    )
    user._state.fields_cache["mentee_kyc"] = stub


def _stub_mentor_kyc(user, *, status="approved", days_ago=45):
    stub = SimpleNamespace(
        status=status,
        reviewed_at=timezone.now() - timedelta(days=days_ago) if status == "approved" else None,
    )
    user._state.fields_cache["mentor_kyc"] = stub


def _patch_compute_level(monkeypatch, level):
    monkeypatch.setattr(
        "apps.nests.levels.compute_level",
        lambda u: {"current_level": level},
    )


def _patch_completed_enrollment(monkeypatch, exists: bool):
    class _FakeQS:
        def exists(self_inner):
            return exists

    class _FakeManager:
        def filter(self_inner, *a, **kw):
            return _FakeQS()

    class _FakeModel:
        objects = _FakeManager()

    # Replace the module-level lookup that can_request_admin's lazy import hits.
    import apps.nests.models_program as mp
    monkeypatch.setattr(mp, "ProgramEnrollment", _FakeModel)


# ─── Eaglet: happy + each gate ──────────────────────────────────────────────

def test_eaglet_eligible_when_all_gates_pass(monkeypatch):
    user = _make_user("e1@test.com", role="eaglet")
    _stub_mentee_kyc(user)
    _patch_compute_level(monkeypatch, level=5)
    _patch_completed_enrollment(monkeypatch, exists=True)

    result = user.can_request_admin()
    assert result == {"eligible": True, "reasons": []}


def test_eaglet_suspended(monkeypatch):
    user = _make_user("e2@test.com", role="eaglet")
    user.is_active = False
    _stub_mentee_kyc(user)
    _patch_compute_level(monkeypatch, level=5)
    _patch_completed_enrollment(monkeypatch, exists=True)

    result = user.can_request_admin()
    assert not result["eligible"]
    assert any("suspended" in r for r in result["reasons"])


def test_eaglet_no_mentee_kyc(monkeypatch):
    user = _make_user("e3@test.com", role="eaglet")
    _patch_compute_level(monkeypatch, level=5)
    _patch_completed_enrollment(monkeypatch, exists=True)

    result = user.can_request_admin()
    assert not result["eligible"]
    assert any("mentee profile must be KYC-approved" in r for r in result["reasons"])


def test_eaglet_mentee_kyc_pending(monkeypatch):
    user = _make_user("e4@test.com", role="eaglet")
    _stub_mentee_kyc(user, status="pending")
    _patch_compute_level(monkeypatch, level=5)
    _patch_completed_enrollment(monkeypatch, exists=True)

    result = user.can_request_admin()
    assert not result["eligible"]
    assert any("mentee profile must be KYC-approved" in r for r in result["reasons"])


def test_eaglet_below_level_3(monkeypatch):
    user = _make_user("e5@test.com", role="eaglet")
    _stub_mentee_kyc(user)
    _patch_compute_level(monkeypatch, level=2)
    _patch_completed_enrollment(monkeypatch, exists=True)

    result = user.can_request_admin()
    assert not result["eligible"]
    assert any("Level 3" in r and "Current level: 2" in r for r in result["reasons"])


def test_eaglet_no_completed_program(monkeypatch):
    user = _make_user("e6@test.com", role="eaglet")
    _stub_mentee_kyc(user)
    _patch_compute_level(monkeypatch, level=5)
    _patch_completed_enrollment(monkeypatch, exists=False)

    result = user.can_request_admin()
    assert not result["eligible"]
    assert any("completed at least one program" in r for r in result["reasons"])


# ─── Eagle path unchanged ────────────────────────────────────────────────────

def test_eagle_eligible_with_approved_kyc_past_30d():
    user = _make_user("m1@test.com", role="eagle")
    _stub_mentor_kyc(user, days_ago=45)

    result = user.can_request_admin()
    assert result == {"eligible": True, "reasons": []}


def test_eagle_without_mentor_kyc():
    user = _make_user("m2@test.com", role="eagle")
    # No mentor_kyc attached.

    result = user.can_request_admin()
    assert not result["eligible"]
    assert any("mentor profile must be KYC-approved" in r for r in result["reasons"])


def test_eagle_kyc_under_30d():
    user = _make_user("m3@test.com", role="eagle")
    _stub_mentor_kyc(user, days_ago=10)

    result = user.can_request_admin()
    assert not result["eligible"]
    # Preserve the existing wording — FE may parse by substring.
    assert any("approved for 10 days" in r for r in result["reasons"])


# ─── Other roles blocked ─────────────────────────────────────────────────────

def test_admin_role_blocked():
    user = _make_user("a@test.com", role="admin")

    result = user.can_request_admin()
    assert not result["eligible"]
    assert any("open to mentors and mentees only" in r for r in result["reasons"])


def test_visitor_role_blocked():
    user = _make_user("v@test.com", role="visitor")

    result = user.can_request_admin()
    assert not result["eligible"]
    assert any("open to mentors and mentees only" in r for r in result["reasons"])


# ─── Invite path bypasses eligibility ────────────────────────────────────────

def test_invite_accept_bypasses_eligibility_gate(monkeypatch):
    """An ineligible eaglet (no KYC, no level, no completion) can still gain
    admin via invite — accept_invite has no role/eligibility check by design."""
    from apps.users.models_admin import AdminInvite
    from apps.users.services.admin_role import accept_invite, hash_invite_token
    import secrets

    user = _make_user("invitee@test.com", role="eaglet")
    # Confirm they would be REJECTED via EOI path.
    _patch_compute_level(monkeypatch, level=1)
    _patch_completed_enrollment(monkeypatch, exists=False)
    assert not user.can_request_admin()["eligible"]

    # Now mint an invite and accept it.
    raw_token = secrets.token_urlsafe(32)
    AdminInvite.objects.create(
        email=user.email,
        token_hash=hash_invite_token(raw_token),
        status=AdminInvite.Status.SENT,
        expires_at=timezone.now() + timedelta(days=7),
    )
    accept_invite(user=user, token=raw_token)

    user.refresh_from_db()
    assert user.is_platform_staff is True

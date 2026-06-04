"""Tests for Mentor Application workflow (plan 16-01)."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient

from apps.users.models_mentor_app import MentorApplication, MentorApplicationAudit
from apps.users.services import mentor_application as svc

pytestmark = pytest.mark.django_db

User = get_user_model()


def _make_user(email, *, role="eaglet", is_platform_staff=False):
    return User.objects.create_user(
        email=email,
        password="TestPassword123!",
        first_name=email.split("@")[0].title(),
        last_name="User",
        role=role,
        is_platform_staff=is_platform_staff,
    )


@pytest.fixture
def eligible(monkeypatch):
    """Force compute_level to report the user mentor-eligible."""
    monkeypatch.setattr(
        "apps.nests.levels.compute_level",
        lambda user: {"mentor_eligible": True},
    )


@pytest.fixture
def ineligible(monkeypatch):
    monkeypatch.setattr(
        "apps.nests.levels.compute_level",
        lambda user: {"mentor_eligible": False},
    )


@pytest.fixture
def mentee():
    return _make_user("mentee@e.test", role="eaglet")


@pytest.fixture
def admin_user():
    u = _make_user("admin@e.test", role="admin", is_platform_staff=True)
    u.is_staff = True
    u.save(update_fields=["is_staff"])
    return u


@pytest.fixture
def api():
    return APIClient()


# ─── Eligibility gate ────────────────────────────────────────────────────────

def test_ineligible_mentee_cannot_submit(api, mentee, ineligible):
    api.force_authenticate(user=mentee)
    resp = api.post(reverse("users:mentor-application"))
    assert resp.status_code == 400
    assert MentorApplication.objects.count() == 0


def test_eligible_mentee_submits(api, mentee, eligible):
    api.force_authenticate(user=mentee)
    resp = api.post(reverse("users:mentor-application"))
    assert resp.status_code == 201
    assert resp.data["data"]["status"] == "submitted"
    assert MentorApplication.objects.filter(user=mentee).count() == 1


def test_eagle_is_not_eligible(mentee, eligible):
    # compute_level says eligible, but role gate blocks non-eaglets.
    mentee.role = User.Role.EAGLE
    mentee.save(update_fields=["role"])
    assert svc.is_eligible(mentee) is False


# ─── Dedupe ──────────────────────────────────────────────────────────────────

def test_duplicate_active_application_rejected(api, mentee, eligible):
    api.force_authenticate(user=mentee)
    assert api.post(reverse("users:mentor-application")).status_code == 201
    resp = api.post(reverse("users:mentor-application"))
    assert resp.status_code == 400
    assert MentorApplication.objects.filter(user=mentee).count() == 1


# ─── Approve flips role + audit ──────────────────────────────────────────────

def test_approve_flips_role_and_audits(mentee, admin_user, eligible):
    app = svc.submit(user=mentee)
    svc.approve(actor=admin_user, application_id=app.id, note="Strong candidate")

    mentee.refresh_from_db()
    app.refresh_from_db()
    assert app.status == "approved"
    assert mentee.role == User.Role.EAGLE
    assert app.audit_entries.filter(action="approved").exists()


def test_admin_cannot_approve_own_application(admin_user, eligible):
    # Make the admin look like an eligible eaglet applicant edge case.
    app = MentorApplication.objects.create(
        user=admin_user, status=MentorApplication.Status.SUBMITTED
    )
    with pytest.raises(svc.MentorApplicationError):
        svc.approve(actor=admin_user, application_id=app.id)


# ─── Reject requires reason + audit ──────────────────────────────────────────

def test_reject_requires_reason(mentee, admin_user, eligible):
    app = svc.submit(user=mentee)
    with pytest.raises(svc.MentorApplicationError):
        svc.reject(actor=admin_user, application_id=app.id, reason="no")


def test_reject_records_audit(mentee, admin_user, eligible):
    app = svc.submit(user=mentee)
    svc.reject(actor=admin_user, application_id=app.id, reason="Insufficient experience")
    app.refresh_from_db()
    assert app.status == "rejected"
    assert app.rejection_reason == "Insufficient experience"
    assert app.audit_entries.filter(action="rejected").exists()


# ─── Withdraw ────────────────────────────────────────────────────────────────

def test_owner_withdraws(api, mentee, eligible):
    app = svc.submit(user=mentee)
    api.force_authenticate(user=mentee)
    resp = api.post(reverse("users:mentor-application-withdraw", args=[app.id]))
    assert resp.status_code == 200
    app.refresh_from_db()
    assert app.status == "withdrawn"


# ─── Admin-only queue ────────────────────────────────────────────────────────

def test_admin_queue_requires_admin(api, mentee, eligible):
    svc.submit(user=mentee)
    api.force_authenticate(user=mentee)
    assert api.get(reverse("users:admin-mentor-application-list")).status_code == 403


def test_admin_queue_lists_submitted(api, mentee, admin_user, eligible):
    svc.submit(user=mentee)
    api.force_authenticate(user=admin_user)
    resp = api.get(reverse("users:admin-mentor-application-list"))
    assert resp.status_code == 200
    assert len(resp.data["data"]) == 1


def test_audit_rows_are_immutable(mentee, eligible):
    svc.submit(user=mentee)
    row = MentorApplicationAudit.objects.first()
    with pytest.raises(RuntimeError):
        row.reason = "tampered"
        row.save()


# ─── Cooldown + email (scope addition, 16-03) ─────────────────────────────────

def test_reject_sends_email_with_reason_and_cooldown(mentee, admin_user, eligible, mailoutbox):
    app = svc.submit(user=mentee)
    svc.reject(actor=admin_user, application_id=app.id, reason="Need more program experience")

    assert len(mailoutbox) == 1
    msg = mailoutbox[0]
    assert mentee.email in msg.to
    assert "mentor application" in msg.subject.lower()
    assert "Need more program experience" in msg.body


def test_approve_sends_email(mentee, admin_user, eligible, mailoutbox):
    app = svc.submit(user=mentee)
    svc.approve(actor=admin_user, application_id=app.id, note="Strong candidate")

    # 1 email for approval; submit() doesn't send an applicant email.
    approval_mails = [m for m in mailoutbox if "mentor" in m.subject.lower() and mentee.email in m.to]
    assert len(approval_mails) == 1


def test_rejected_user_blocked_by_cooldown(mentee, admin_user, eligible):
    app = svc.submit(user=mentee)
    svc.reject(actor=admin_user, application_id=app.id, reason="Need more program experience")

    # Re-apply attempt during cooldown → CooldownError.
    with pytest.raises(svc.MentorApplicationCooldownError) as exc_info:
        svc.submit(user=mentee)
    assert exc_info.value.available_at is not None


def test_cooldown_expires_after_window(mentee, admin_user, eligible, settings):
    settings.MENTOR_APPLICATION_REJECT_COOLDOWN_DAYS = 30
    app = svc.submit(user=mentee)
    svc.reject(actor=admin_user, application_id=app.id, reason="Need more program experience")

    # Backdate reviewed_at to before the cooldown window.
    from datetime import timedelta
    from django.utils import timezone
    app.refresh_from_db()
    app.reviewed_at = timezone.now() - timedelta(days=31)
    app.save(update_fields=["reviewed_at"])

    # Should succeed now.
    new_app = svc.submit(user=mentee)
    assert new_app.id != app.id
    assert new_app.status == "submitted"


def test_withdrawn_has_no_cooldown(api, mentee, eligible):
    api.force_authenticate(user=mentee)
    resp = api.post(reverse("users:mentor-application"))
    app_id = resp.data["data"]["id"]
    api.post(reverse("users:mentor-application-withdraw", args=[app_id]))

    # Immediate re-submit after withdraw must succeed (no cooldown).
    resp2 = api.post(reverse("users:mentor-application"))
    assert resp2.status_code == 201

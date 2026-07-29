"""
Manual-award governance — Phase 31-01.

Before this phase a mentor's manual award was bounded only by a hardcoded
`max_value=1000` in the serializer, with no rate limit, so 1000 points was a
per-click figure. These tests lock the contract: a superadmin-set ceiling and a
per-mentor daily budget, enforced in the service (the chokepoint), with admins
exempt and the ledger never mutated by the audit tool.
"""

from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.nests.models import Nest, NestMembership
from apps.points.models import PointsPolicy, PointTransaction
from apps.points.services import PointService

pytestmark = pytest.mark.django_db

AWARD_URL = "/api/v1/points/award/"
BUDGET_URL = "/api/v1/points/award-budget/"
POLICY_URL = "/api/v1/points/policy/"


def _auth(api_client, user):
    token = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return api_client


@pytest.fixture
def policy():
    """Singleton policy at the seeded defaults (25 / 250)."""
    p = PointsPolicy.load()
    p.max_manual_award = 25
    p.daily_points_per_mentor = 250
    p.is_enforced = True
    p.save()
    return p


@pytest.fixture
def mentor(user_factory):
    return user_factory(email="mentor31@test.com", role="eagle",
                        first_name="Men", last_name="Tor")


@pytest.fixture
def mentee(user_factory):
    return user_factory(email="mentee31@test.com", role="eaglet",
                        first_name="Men", last_name="Tee")


@pytest.fixture
def nest(mentor, mentee):
    n = Nest.objects.create(eagle=mentor, name="Governance Nest", category="faith")
    NestMembership.objects.create(nest=n, user=mentee, status="active")
    return n


def _award(mentor, mentee, points, nest, description="Great work on the assignment"):
    return PointService.award_manual_points(
        eagle=mentor, eaglet=mentee, points=points,
        description=description, nest=nest,
    )


# ---------------------------------------------------------------------------
# AC-1: per-award ceiling
# ---------------------------------------------------------------------------

def test_award_at_exactly_the_ceiling_succeeds(policy, mentor, mentee, nest):
    txn = _award(mentor, mentee, 25, nest)
    assert txn.points == 25


def test_award_above_ceiling_is_rejected(policy, mentor, mentee, nest):
    with pytest.raises(ValidationError) as exc:
        _award(mentor, mentee, 26, nest)
    assert "25" in str(exc.value)
    assert not PointTransaction.objects.filter(awarded_by=mentor).exists()


def test_raising_the_policy_takes_effect_without_a_code_change(policy, mentor, mentee, nest):
    """The whole point of the phase: the limit is data, not a constant."""
    with pytest.raises(ValidationError):
        _award(mentor, mentee, 50, nest)

    policy.max_manual_award = 50
    policy.save()

    txn = _award(mentor, mentee, 50, nest)
    assert txn.points == 50


# ---------------------------------------------------------------------------
# AC-2: daily per-mentor budget
# ---------------------------------------------------------------------------

def test_daily_budget_blocks_when_exceeded(policy, mentor, mentee, nest):
    # 10 × 25 = 250 → budget exactly exhausted
    for _ in range(10):
        _award(mentor, mentee, 25, nest)

    with pytest.raises(ValidationError) as exc:
        _award(mentor, mentee, 1, nest)
    assert "0 of 250" in str(exc.value)


def test_partial_budget_remaining_allows_smaller_award(policy, mentor, mentee, nest):
    for _ in range(9):
        _award(mentor, mentee, 25, nest)  # 225 used, 25 left

    txn = _award(mentor, mentee, 25, nest)
    assert txn.points == 25
    assert PointService._manual_points_awarded_today(mentor) == 250


def test_yesterdays_awards_do_not_count_toward_today(policy, mentor, mentee, nest):
    txn = _award(mentor, mentee, 25, nest)
    # Backdate it a day (created_at is auto_now_add, so update after insert).
    PointTransaction.objects.filter(pk=txn.pk).update(
        created_at=timezone.now() - timedelta(days=1)
    )

    assert PointService._manual_points_awarded_today(mentor) == 0
    assert _award(mentor, mentee, 25, nest).points == 25


# ---------------------------------------------------------------------------
# AC-3: admins bypass both limits
# ---------------------------------------------------------------------------

def test_admin_bypasses_ceiling_and_daily_budget(policy, user_factory, mentee, nest):
    admin = user_factory(email="admin31@test.com", role="admin",
                         is_staff=True, is_superuser=True)
    # Far above both the per-award ceiling (25) and the daily budget (250).
    txn = PointService.award_manual_points(
        eagle=admin, eaglet=mentee, points=5000,
        description="Admin correction after review", nest=nest,
    )
    assert txn.points == 5000


def test_admin_awards_do_not_consume_a_mentors_budget(policy, user_factory, mentor, mentee, nest):
    admin = user_factory(email="admin31b@test.com", role="admin",
                         is_staff=True, is_superuser=True)
    PointService.award_manual_points(
        eagle=admin, eaglet=mentee, points=500,
        description="Admin bulk correction", nest=nest,
    )
    # The mentor's own budget is untouched.
    assert PointService._manual_points_awarded_today(mentor) == 0
    assert _award(mentor, mentee, 25, nest).points == 25


def test_disabling_enforcement_lifts_limits(policy, mentor, mentee, nest):
    policy.is_enforced = False
    policy.save()
    txn = _award(mentor, mentee, 900, nest)
    assert txn.points == 900


# ---------------------------------------------------------------------------
# AC-4: budget endpoint
# ---------------------------------------------------------------------------

def test_budget_endpoint_reports_remaining(policy, api_client, mentor, mentee, nest):
    _award(mentor, mentee, 25, nest)
    _award(mentor, mentee, 25, nest)  # 50 used

    resp = _auth(api_client, mentor).get(BUDGET_URL)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["max_per_award"] == 25
    assert data["daily_limit"] == 250
    assert data["used_today"] == 50
    assert data["remaining"] == 200
    assert data["is_enforced"] is True


# ---------------------------------------------------------------------------
# AC-5: superadmin-only policy CRUD
# ---------------------------------------------------------------------------

def test_superadmin_can_read_and_update_policy(policy, api_client, user_factory):
    su = user_factory(email="su31@test.com", role="admin",
                      is_staff=True, is_superuser=True)
    client = _auth(api_client, su)

    assert client.get(POLICY_URL).status_code == 200

    resp = client.patch(POLICY_URL, {"max_manual_award": 40}, format="json")
    assert resp.status_code == 200
    assert resp.json()["data"]["max_manual_award"] == 40
    assert PointsPolicy.load().max_manual_award == 40


def test_mentor_cannot_read_or_change_policy(policy, api_client, mentor):
    client = _auth(api_client, mentor)
    assert client.get(POLICY_URL).status_code == 403
    assert client.patch(POLICY_URL, {"max_manual_award": 9999},
                        format="json").status_code == 403


def test_scoped_admin_cannot_change_policy(policy, api_client, user_factory):
    """Dual-role admins must not raise the ceiling that governs them."""
    scoped = user_factory(email="scoped31@test.com", role="eagle",
                          is_platform_staff=True)
    resp = _auth(api_client, scoped).patch(
        POLICY_URL, {"max_manual_award": 9999}, format="json"
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# AC-6: audit command reports without writing
# ---------------------------------------------------------------------------

def test_audit_command_reports_and_never_writes(policy, mentor, mentee, nest):
    # Create an over-ceiling award while enforcement is off, to simulate history.
    policy.is_enforced = False
    policy.save()
    _award(mentor, mentee, 900, nest)
    policy.is_enforced = True
    policy.save()

    before = PointTransaction.objects.count()
    before_points = list(PointTransaction.objects.values_list("points", flat=True))

    out = StringIO()
    call_command("audit_manual_awards", stdout=out)
    output = out.getvalue()

    assert "above the 25-point ceiling" in output
    assert "daily budget" in output
    # Ledger completely untouched.
    assert PointTransaction.objects.count() == before
    assert list(PointTransaction.objects.values_list("points", flat=True)) == before_points


def test_audit_command_clean_when_no_violations(policy, mentor, mentee, nest):
    _award(mentor, mentee, 25, nest)
    out = StringIO()
    call_command("audit_manual_awards", stdout=out)
    assert "No manual awards exceed the current policy." in out.getvalue()

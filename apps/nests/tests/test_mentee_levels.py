"""
Tests for compute_level service (plan 14-04).

Covers: role gating, no-enrollment baseline, threshold transitions, lifetime
carry-forward across multiple windows, window boundary exclusion, qualifying
status set, and mentor_eligible flip at level 5.
"""

import pytest
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.nests.models import Nest
from apps.nests.models_program import (
    MenteeLevelConfig,
    Program,
    ProgramEnrollment,
)
from apps.nests.levels import compute_level
from apps.points.models import PointTransaction


User = get_user_model()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_DEFAULTS = [
    (1, "Hatchling", 0, False),
    (2, "Fledgling", 100, False),
    (3, "Flyer", 300, False),
    (4, "Soaring", 750, False),
    (5, "Master Eagle", 1500, True),
]


@pytest.fixture(autouse=True)
def _seed_levels(db):
    """Re-seed level configs per test (transactional rollback wipes data)."""
    for level, name, pts, mentor in _DEFAULTS:
        MenteeLevelConfig.objects.update_or_create(
            level=level,
            defaults={"name": name, "points_required": pts,
                      "unlocks_mentor_application": mentor, "description": ""},
        )


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle-l@test.com", password="pass",
        role=User.Role.EAGLE, first_name="E", last_name="A",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet-l@test.com", password="pass",
        role=User.Role.EAGLET, first_name="M", last_name="N",
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="Levels Nest", eagle=eagle)


@pytest.fixture
def program(db, nest):
    return Program.objects.create(
        nest=nest, name="Levels Program", status=Program.Status.ACTIVE,
    )


def _enrollment(program, mentee, status, started_offset_days=-30, ended_offset_days=None):
    now = timezone.now()
    started = now + timedelta(days=started_offset_days)
    ended = now + timedelta(days=ended_offset_days) if ended_offset_days is not None else None
    return ProgramEnrollment.objects.create(
        program=program, mentee=mentee, status=status,
        started_at=started, ended_at=ended,
    )


def _award(user, points, days_ago):
    """Create a PointTransaction with custom created_at (TimestampMixin auto_now_add bypass)."""
    txn = PointTransaction.objects.create(
        user=user, points=points, activity_type="manual_award",
    )
    PointTransaction.objects.filter(pk=txn.pk).update(
        created_at=timezone.now() - timedelta(days=days_ago),
    )
    return txn


# ---------------------------------------------------------------------------
# Role gating + baseline
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_non_eaglet_returns_zero_block(eagle):
    out = compute_level(eagle)
    assert out["current_level"] == 0
    assert out["points_total"] == 0
    assert out["mentor_eligible"] is False


@pytest.mark.django_db
def test_eaglet_no_enrollments_returns_zero_block(eaglet):
    out = compute_level(eaglet)
    assert out["current_level"] == 0
    assert out["next_level"] == 1
    assert out["mentor_eligible"] is False


@pytest.mark.django_db
def test_pending_enrollment_does_not_qualify(eaglet, program):
    _enrollment(program, eaglet, ProgramEnrollment.Status.PENDING)
    _award(eaglet, 500, days_ago=5)
    out = compute_level(eaglet)
    assert out["current_level"] == 0
    assert out["points_total"] == 0


@pytest.mark.django_db
def test_rejected_enrollment_does_not_qualify(eaglet, program):
    _enrollment(
        program, eaglet, ProgramEnrollment.Status.REJECTED,
        started_offset_days=None or -10, ended_offset_days=-5,
    )
    out = compute_level(eaglet)
    assert out["current_level"] == 0


# ---------------------------------------------------------------------------
# Threshold transitions
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_active_enrollment_below_first_threshold(eaglet, program):
    _enrollment(program, eaglet, ProgramEnrollment.Status.ACTIVE)
    _award(eaglet, 50, days_ago=2)
    out = compute_level(eaglet)
    # L1 threshold is 0, so 50 pts -> L1 already
    assert out["current_level"] == 1
    assert out["current_level_name"] == "Hatchling"
    assert out["next_level"] == 2
    assert out["points_to_next"] == 50  # 100 - 50


@pytest.mark.django_db
def test_crosses_into_level_2(eaglet, program):
    _enrollment(program, eaglet, ProgramEnrollment.Status.ACTIVE)
    _award(eaglet, 100, days_ago=2)
    out = compute_level(eaglet)
    assert out["current_level"] == 2
    assert out["current_level_name"] == "Fledgling"
    assert out["points_to_next"] == 200


@pytest.mark.django_db
def test_reaches_level_5_sets_mentor_eligible(eaglet, program):
    _enrollment(program, eaglet, ProgramEnrollment.Status.ACTIVE)
    _award(eaglet, 1500, days_ago=3)
    out = compute_level(eaglet)
    assert out["current_level"] == 5
    assert out["current_level_name"] == "Master Eagle"
    assert out["next_level"] is None
    assert out["points_to_next"] is None
    assert out["mentor_eligible"] is True


# ---------------------------------------------------------------------------
# Lifetime carry-forward
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_completed_enrollment_carries_points_forward(eaglet, program):
    _enrollment(
        program, eaglet, ProgramEnrollment.Status.COMPLETED,
        started_offset_days=-60, ended_offset_days=-30,
    )
    _award(eaglet, 200, days_ago=45)
    out = compute_level(eaglet)
    assert out["points_total"] == 200
    assert out["current_level"] == 2


@pytest.mark.django_db
def test_two_separate_windows_sum(eaglet, nest):
    p1 = Program.objects.create(nest=nest, name="P1", status=Program.Status.ARCHIVED)
    p2 = Program.objects.create(nest=nest, name="P2", status=Program.Status.ACTIVE)
    _enrollment(
        p1, eaglet, ProgramEnrollment.Status.COMPLETED,
        started_offset_days=-90, ended_offset_days=-60,
    )
    _enrollment(p2, eaglet, ProgramEnrollment.Status.ACTIVE, started_offset_days=-10)
    _award(eaglet, 150, days_ago=75)  # in p1 window
    _award(eaglet, 150, days_ago=5)   # in p2 window
    out = compute_level(eaglet)
    assert out["points_total"] == 300
    assert out["current_level"] == 3


@pytest.mark.django_db
def test_points_outside_windows_excluded(eaglet, program):
    _enrollment(
        program, eaglet, ProgramEnrollment.Status.COMPLETED,
        started_offset_days=-30, ended_offset_days=-10,
    )
    _award(eaglet, 500, days_ago=60)  # before window start
    _award(eaglet, 500, days_ago=2)   # after window end
    out = compute_level(eaglet)
    assert out["points_total"] == 0
    # L1 threshold is 0, so a qualifying enrollment + 0 points still lands at L1
    assert out["current_level"] == 1


@pytest.mark.django_db
def test_overlapping_windows_no_double_count(eaglet, nest):
    p1 = Program.objects.create(nest=nest, name="P1", status=Program.Status.ARCHIVED)
    p2 = Program.objects.create(nest=nest, name="P2", status=Program.Status.ACTIVE)
    _enrollment(
        p1, eaglet, ProgramEnrollment.Status.COMPLETED,
        started_offset_days=-20, ended_offset_days=-5,
    )
    _enrollment(p2, eaglet, ProgramEnrollment.Status.ACTIVE, started_offset_days=-10)
    _award(eaglet, 100, days_ago=8)  # in BOTH windows (overlap)
    out = compute_level(eaglet)
    assert out["points_total"] == 100  # not 200


# ---------------------------------------------------------------------------
# Released / opted-out qualify; rejected/pending do not
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_released_enrollment_qualifies(eaglet, program):
    _enrollment(
        program, eaglet, ProgramEnrollment.Status.RELEASED,
        started_offset_days=-40, ended_offset_days=-10,
    )
    _award(eaglet, 300, days_ago=20)
    out = compute_level(eaglet)
    assert out["current_level"] == 3


@pytest.mark.django_db
def test_opted_out_enrollment_qualifies(eaglet, program):
    _enrollment(
        program, eaglet, ProgramEnrollment.Status.OPTED_OUT,
        started_offset_days=-40, ended_offset_days=-10,
    )
    _award(eaglet, 100, days_ago=20)
    out = compute_level(eaglet)
    assert out["current_level"] == 2


# ---------------------------------------------------------------------------
# Edge: no MenteeLevelConfig rows (defensive)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_no_level_configs_returns_zero_block(eaglet, program):
    MenteeLevelConfig.objects.all().delete()
    _enrollment(program, eaglet, ProgramEnrollment.Status.ACTIVE)
    _award(eaglet, 5000, days_ago=2)
    out = compute_level(eaglet)
    assert out["current_level"] == 0
    assert out["next_level"] is None
    assert out["points_to_next"] is None

"""
Tests for HasActiveProgram gating switch-on (plan 14-03).

Covers REST gating on assignments, content items, chat, and nest resources.
WS gating is exercised by the consumer's connect() guard but tested via the
permission helper to keep the suite fast (no channels test runner).
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from apps.content.models import Assignment
from apps.nests.models import Nest, NestMembership
from apps.nests.models_program import Program, ProgramEnrollment
from apps.nests.permissions import HasActiveProgram, NoActiveProgramDenied
from apps.nests.services import EnrollmentService, InvalidTransition

User = get_user_model()


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="g_eagle@test.com", password="p", role=User.Role.EAGLE,
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="g_eaglet@test.com", password="p", role=User.Role.EAGLET,
    )


@pytest.fixture
def staff(db):
    return User.objects.create_user(
        email="g_staff@test.com", password="p", role=User.Role.ADMIN, is_staff=True,
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="G Nest", eagle=eagle)


@pytest.fixture
def program(db, nest):
    return Program.objects.create(
        nest=nest, name="GP", status=Program.Status.ACTIVE,
    )


def _client(user):
    c = APIClient()
    c.force_authenticate(user=user)
    return c


# ---------------------------------------------------------------------------
# HasActiveProgram permission
# ---------------------------------------------------------------------------


class TestHasActiveProgramPermission:
    def test_eaglet_without_enrollment_raises(self, db, eaglet):
        from rest_framework.test import APIRequestFactory
        req = APIRequestFactory().get("/")
        req.user = eaglet
        perm = HasActiveProgram()
        with pytest.raises(NoActiveProgramDenied):
            perm.has_permission(req, None)

    def test_eaglet_with_active_enrollment_passes(self, db, eaglet, program):
        ProgramEnrollment.objects.create(
            program=program, mentee=eaglet,
            status=ProgramEnrollment.Status.ACTIVE,
        )
        from rest_framework.test import APIRequestFactory
        req = APIRequestFactory().get("/")
        req.user = eaglet
        assert HasActiveProgram().has_permission(req, None) is True

    def test_eagle_bypasses(self, db, eagle):
        from rest_framework.test import APIRequestFactory
        req = APIRequestFactory().get("/")
        req.user = eagle
        assert HasActiveProgram().has_permission(req, None) is True

    def test_staff_bypasses(self, db, staff):
        from rest_framework.test import APIRequestFactory
        req = APIRequestFactory().get("/")
        req.user = staff
        assert HasActiveProgram().has_permission(req, None) is True


# ---------------------------------------------------------------------------
# Endpoint integration — assignments
# ---------------------------------------------------------------------------


class TestAssignmentEndpointGating:
    def test_eaglet_without_enrollment_blocked(self, db, eaglet):
        resp = _client(eaglet).get("/api/v1/content/assignments/?my_assignments=true")
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        body = resp.json() if hasattr(resp, "json") else resp.data
        assert "no_active_program" in str(body) or "active program" in str(body).lower()

    def test_eaglet_with_active_enrollment_allowed(self, db, eaglet, program):
        ProgramEnrollment.objects.create(
            program=program, mentee=eaglet,
            status=ProgramEnrollment.Status.ACTIVE,
        )
        resp = _client(eaglet).get("/api/v1/content/assignments/?my_assignments=true")
        assert resp.status_code == status.HTTP_200_OK

    def test_eagle_bypasses_assignment_gate(self, db, eagle):
        resp = _client(eagle).get("/api/v1/content/assignments/?my_assignments=true")
        assert resp.status_code == status.HTTP_200_OK

    def test_staff_bypasses_assignment_gate(self, db, staff):
        resp = _client(staff).get("/api/v1/content/assignments/?my_assignments=true")
        assert resp.status_code == status.HTTP_200_OK

    def test_completed_enrollment_blocks_eaglet(self, db, eaglet, program, eagle):
        e = ProgramEnrollment.objects.create(
            program=program, mentee=eaglet,
            status=ProgramEnrollment.Status.ACTIVE,
        )
        EnrollmentService.complete(enrollment_id=e.id, actor=eagle, force=True)
        resp = _client(eaglet).get("/api/v1/content/assignments/?my_assignments=true")
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ---------------------------------------------------------------------------
# EnrollmentService.complete() with evaluator
# ---------------------------------------------------------------------------


class TestCompleteWithEvaluator:
    def test_complete_rejects_when_objectives_unmet(self, db, eaglet, program, eagle):
        e = ProgramEnrollment.objects.create(
            program=program, mentee=eaglet,
            status=ProgramEnrollment.Status.ACTIVE,
            rules_snapshot={
                "program_id": str(program.id),
                "objectives": [{
                    "id": "o", "title": "T",
                    "rules": [{"id": "r", "rule_type": "points_earned", "target": 999, "config": {}}],
                }],
            },
        )
        with pytest.raises(InvalidTransition) as exc:
            EnrollmentService.complete(enrollment_id=e.id, actor=eagle)
        assert exc.value.error_code == "objectives_incomplete"

    def test_force_true_bypasses_for_staff(self, db, eaglet, program, staff):
        e = ProgramEnrollment.objects.create(
            program=program, mentee=eaglet,
            status=ProgramEnrollment.Status.ACTIVE,
            rules_snapshot={
                "program_id": str(program.id),
                "objectives": [{
                    "id": "o", "title": "T",
                    "rules": [{"id": "r", "rule_type": "points_earned", "target": 999, "config": {}}],
                }],
            },
        )
        result = EnrollmentService.complete(
            enrollment_id=e.id, actor=staff, force=True,
        )
        assert result.status == ProgramEnrollment.Status.COMPLETED

    def test_complete_succeeds_when_all_rules_met(self, db, eaglet, program, eagle):
        from apps.points.models import PointTransaction

        e = ProgramEnrollment.objects.create(
            program=program, mentee=eaglet,
            status=ProgramEnrollment.Status.ACTIVE,
            started_at=__import__("django").utils.timezone.now() - __import__("datetime").timedelta(days=1),
            rules_snapshot={
                "program_id": str(program.id),
                "objectives": [{
                    "id": "o", "title": "T",
                    "rules": [{"id": "r", "rule_type": "points_earned", "target": 10, "config": {}}],
                }],
            },
        )
        PointTransaction.objects.create(user=eaglet, points=20, activity_type="check_in")
        result = EnrollmentService.complete(enrollment_id=e.id, actor=eagle)
        assert result.status == ProgramEnrollment.Status.COMPLETED


# ---------------------------------------------------------------------------
# Resource gating
# ---------------------------------------------------------------------------


class TestResourceEndpointGating:
    def test_eaglet_without_active_blocked_on_resources(self, db, eaglet, nest):
        # Need membership to satisfy IsNestMember, but no enrollment
        NestMembership.objects.create(nest=nest, user=eaglet)
        resp = _client(eaglet).get(f"/api/v1/nests/{nest.id}/resources/")
        assert resp.status_code == status.HTTP_403_FORBIDDEN

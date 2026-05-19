"""
Tests for ProgramEnrollment lifecycle, signals, permissions, endpoints (plan 14-02).
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from apps.nests.models import Nest, NestMembership
from apps.nests.models_program import (
    Program,
    ProgramEnrollment,
    ProgramExitRequest,
)
from apps.nests.services import (
    EnrollmentService,
    AlreadyEnrolled,
    NoActiveProgram,
    InvalidTransition,
)

User = get_user_model()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="One",
    )


@pytest.fixture
def other_eagle(db):
    return User.objects.create_user(
        email="eagle2@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="Two",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com", password="pass",
        role=User.Role.EAGLET, first_name="Eaglet", last_name="One",
    )


@pytest.fixture
def other_eaglet(db):
    return User.objects.create_user(
        email="eaglet2@test.com", password="pass",
        role=User.Role.EAGLET, first_name="Eaglet", last_name="Two",
    )


@pytest.fixture
def staff(db):
    return User.objects.create_user(
        email="staff@test.com", password="pass",
        role=User.Role.ADMIN, first_name="Staff", last_name="User",
        is_staff=True,
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="Eagle Nest", eagle=eagle)


@pytest.fixture
def other_nest(db, other_eagle):
    return Nest.objects.create(name="Other Nest", eagle=other_eagle)


@pytest.fixture
def active_program(db, nest):
    return Program.objects.create(
        nest=nest, name="Active Program", status=Program.Status.ACTIVE,
    )


@pytest.fixture
def other_active_program(db, other_nest):
    return Program.objects.create(
        nest=other_nest, name="Other Active", status=Program.Status.ACTIVE,
    )


@pytest.fixture
def auth_client():
    def _auth(user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client
    return _auth


# ---------------------------------------------------------------------------
# Service: apply
# ---------------------------------------------------------------------------


class TestApply:
    def test_mentee_can_apply_to_nest_with_active_program(
        self, eaglet, nest, active_program
    ):
        enrollment = EnrollmentService.apply(mentee=eaglet, nest=nest, message="hi")
        assert enrollment.status == ProgramEnrollment.Status.PENDING
        assert enrollment.program_id == active_program.id
        assert enrollment.application_message == "hi"

    def test_apply_fails_when_no_active_program(self, eaglet, nest):
        # Only a draft program exists
        Program.objects.create(nest=nest, name="Draft", status=Program.Status.DRAFT)
        with pytest.raises(NoActiveProgram):
            EnrollmentService.apply(mentee=eaglet, nest=nest)

    def test_apply_fails_when_mentee_has_pending_elsewhere(
        self, eaglet, nest, active_program, other_active_program, other_nest
    ):
        EnrollmentService.apply(mentee=eaglet, nest=nest)
        with pytest.raises(AlreadyEnrolled):
            EnrollmentService.apply(mentee=eaglet, nest=other_nest)

    def test_apply_fails_when_mentee_has_active_elsewhere(
        self, eaglet, nest, active_program, other_active_program, other_nest, eagle
    ):
        e1 = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e1.id, reviewer=eagle)
        with pytest.raises(AlreadyEnrolled):
            EnrollmentService.apply(mentee=eaglet, nest=other_nest)

    def test_apply_rejected_for_eagle_role(self, eagle, nest, active_program):
        from rest_framework.exceptions import PermissionDenied
        with pytest.raises(PermissionDenied):
            EnrollmentService.apply(mentee=eagle, nest=nest)


# ---------------------------------------------------------------------------
# Service: approve
# ---------------------------------------------------------------------------


class TestApprove:
    def test_approve_sets_started_at_and_active_status(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        result = EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        assert result.status == ProgramEnrollment.Status.ACTIVE
        assert result.started_at is not None
        assert result.reviewed_by_id == eagle.id

    def test_approve_snapshots_rules(
        self, eaglet, nest, active_program, eagle
    ):
        from apps.nests.models_program import ProgramObjective, ProgramObjectiveRule
        obj = ProgramObjective.objects.create(program=active_program, title="O1")
        ProgramObjectiveRule.objects.create(
            objective=obj,
            rule_type=ProgramObjectiveRule.RuleType.MODULES_COMPLETED,
            target=5,
        )
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        result = EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        snap = result.rules_snapshot
        assert snap["program_id"] == str(active_program.id)
        assert len(snap["objectives"]) == 1
        assert snap["objectives"][0]["rules"][0]["target"] == 5

    def test_approve_creates_or_activates_nest_membership(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        membership = NestMembership.objects.get(nest=nest, user=eaglet)
        assert membership.status == NestMembership.Status.ACTIVE

    def test_approve_fails_for_non_pending_enrollment(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        with pytest.raises(InvalidTransition):
            EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)

    def test_approve_fails_when_mentee_already_active_elsewhere(
        self, eaglet, nest, active_program, other_active_program, other_nest, eagle, other_eagle
    ):
        e1 = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e1.id, reviewer=eagle)
        # Manually create a second pending one (bypassing service apply check)
        e2 = ProgramEnrollment.objects.create(
            program=other_active_program, mentee=eaglet,
        )
        with pytest.raises(AlreadyEnrolled):
            EnrollmentService.approve(enrollment_id=e2.id, reviewer=other_eagle)


# ---------------------------------------------------------------------------
# Service: reject / release / complete
# ---------------------------------------------------------------------------


class TestRejectReleaseComplete:
    def test_reject_sets_terminal_status_and_no_membership(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        result = EnrollmentService.reject(
            enrollment_id=e.id, reviewer=eagle, reason="no fit",
        )
        assert result.status == ProgramEnrollment.Status.REJECTED
        assert result.exit_reason == "no fit"
        assert not NestMembership.objects.filter(nest=nest, user=eaglet).exists()

    def test_release_sets_terminal_status_and_inactive_membership(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        result = EnrollmentService.release(
            enrollment_id=e.id, actor=eagle, reason="time up",
        )
        assert result.status == ProgramEnrollment.Status.RELEASED
        m = NestMembership.objects.get(nest=nest, user=eaglet)
        assert m.status == NestMembership.Status.INACTIVE

    def test_release_fails_for_non_active_enrollment(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        with pytest.raises(InvalidTransition):
            EnrollmentService.release(enrollment_id=e.id, actor=eagle)

    def test_complete_sets_terminal_status(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        result = EnrollmentService.complete(enrollment_id=e.id, actor=eagle, force=True)
        assert result.status == ProgramEnrollment.Status.COMPLETED

    def test_complete_fails_for_non_active_enrollment(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        with pytest.raises(InvalidTransition):
            EnrollmentService.complete(enrollment_id=e.id, actor=eagle)


# ---------------------------------------------------------------------------
# Service: opt-out
# ---------------------------------------------------------------------------


class TestOptOut:
    def test_mentee_can_request_opt_out_of_active_enrollment(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        req = EnrollmentService.request_opt_out(
            enrollment_id=e.id, mentee=eaglet, reason="moving away",
        )
        assert req.status == ProgramExitRequest.Status.PENDING

    def test_mentee_cannot_self_finalize_exit(
        self, auth_client, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        req = EnrollmentService.request_opt_out(
            enrollment_id=e.id, mentee=eaglet, reason="r",
        )
        client = auth_client(eaglet)
        resp = client.post(
            f"/api/v1/program-exit-requests/{req.id}/decide/",
            {"approve": True}, format="json",
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        e.refresh_from_db()
        assert e.status == ProgramEnrollment.Status.ACTIVE

    def test_mentor_can_approve_exit_request(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        req = EnrollmentService.request_opt_out(
            enrollment_id=e.id, mentee=eaglet, reason="r",
        )
        result = EnrollmentService.decide_opt_out(
            exit_request_id=req.id, decider=eagle, approve=True,
        )
        assert result.status == ProgramExitRequest.Status.APPROVED
        e.refresh_from_db()
        assert e.status == ProgramEnrollment.Status.OPTED_OUT

    def test_mentor_can_deny_exit_request(
        self, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        req = EnrollmentService.request_opt_out(
            enrollment_id=e.id, mentee=eaglet, reason="r",
        )
        EnrollmentService.decide_opt_out(
            exit_request_id=req.id, decider=eagle, approve=False, note="hang in",
        )
        e.refresh_from_db()
        assert e.status == ProgramEnrollment.Status.ACTIVE

    def test_only_one_pending_exit_per_enrollment(
        self, eaglet, nest, active_program, eagle
    ):
        from rest_framework.exceptions import ValidationError
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        EnrollmentService.request_opt_out(
            enrollment_id=e.id, mentee=eaglet, reason="r1",
        )
        with pytest.raises(ValidationError):
            EnrollmentService.request_opt_out(
                enrollment_id=e.id, mentee=eaglet, reason="r2",
            )


# ---------------------------------------------------------------------------
# Endpoint permissions
# ---------------------------------------------------------------------------


class TestEndpointPermissions:
    def test_eagle_cannot_approve_other_nest_enrollment(
        self, auth_client, eaglet, nest, active_program, other_eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        client = auth_client(other_eagle)
        resp = client.post(f"/api/v1/program-enrollments/{e.id}/approve/")
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    def test_eaglet_cannot_approve_own_enrollment(
        self, auth_client, eaglet, nest, active_program
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        client = auth_client(eaglet)
        resp = client.post(f"/api/v1/program-enrollments/{e.id}/approve/")
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    def test_nest_enroll_endpoint_creates_enrollment(
        self, auth_client, eaglet, nest, active_program
    ):
        client = auth_client(eaglet)
        resp = client.post(
            f"/api/v1/nests/{nest.id}/enroll/",
            {"message": "please"}, format="json",
        )
        assert resp.status_code == status.HTTP_201_CREATED, resp.data
        assert ProgramEnrollment.objects.filter(mentee=eaglet, program=active_program).exists()

    def test_nest_enroll_returns_400_when_no_active_program(
        self, auth_client, eaglet, nest
    ):
        client = auth_client(eaglet)
        resp = client.post(f"/api/v1/nests/{nest.id}/enroll/", {}, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert resp.data["error"]["code"] == "no_active_program"

    def test_my_active_returns_active_enrollment(
        self, auth_client, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        client = auth_client(eaglet)
        resp = client.get("/api/v1/program-enrollments/my-active/")
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["data"]["id"] == str(e.id)

    def test_my_active_returns_null_when_no_active(self, auth_client, eaglet):
        client = auth_client(eaglet)
        resp = client.get("/api/v1/program-enrollments/my-active/")
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["data"] is None

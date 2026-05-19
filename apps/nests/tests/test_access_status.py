"""
Tests for /api/v1/auth/me/ access_status payload (plan 14-02).
"""

import json

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from apps.nests.models import Nest
from apps.nests.models_program import Program, ProgramEnrollment
from apps.nests.services import EnrollmentService

User = get_user_model()


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="One",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com", password="pass",
        role=User.Role.EAGLET, first_name="Eaglet", last_name="One",
    )


@pytest.fixture
def admin_user(db):
    return User.objects.create_user(
        email="admin@test.com", password="pass",
        role=User.Role.ADMIN, first_name="Admin", last_name="User",
        is_staff=True,
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="Eagle Nest", eagle=eagle)


@pytest.fixture
def active_program(db, nest):
    return Program.objects.create(
        nest=nest, name="Active P", status=Program.Status.ACTIVE,
    )


@pytest.fixture
def auth_client():
    def _auth(user):
        c = APIClient()
        c.force_authenticate(user=user)
        return c
    return _auth


class TestAccessStatusPayload:
    def test_eaglet_with_no_enrollment_has_locked_features(self, auth_client, eaglet):
        client = auth_client(eaglet)
        resp = client.get("/api/v1/auth/me/")
        assert resp.status_code == status.HTTP_200_OK
        access = resp.data["data"]["access_status"]
        assert access["has_active_program"] is False
        assert access["active_program"] is None
        assert access["pending_program_request"] is None
        # Plan 14.5-01 added 'leaderboard' to the locked set.
        assert set(access["locked_features"]) == {"assignments", "messages", "resources", "leaderboard"}

    def test_eaglet_with_pending_request_shows_pending_block_and_still_locked(
        self, auth_client, eaglet, nest, active_program
    ):
        EnrollmentService.apply(mentee=eaglet, nest=nest)
        client = auth_client(eaglet)
        resp = client.get("/api/v1/auth/me/")
        access = resp.data["data"]["access_status"]
        assert access["has_active_program"] is False
        assert access["pending_program_request"] is not None
        assert access["pending_program_request"]["nest_name"] == "Eagle Nest"
        assert access["locked_features"]  # still locked

    def test_eaglet_with_active_enrollment_unlocks_features(
        self, auth_client, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        client = auth_client(eaglet)
        resp = client.get("/api/v1/auth/me/")
        access = resp.data["data"]["access_status"]
        assert access["has_active_program"] is True
        assert access["active_program"]["program_name"] == "Active P"
        assert access["locked_features"] == []

    def test_eagle_response_has_no_access_status_block(self, auth_client, eagle):
        client = auth_client(eagle)
        resp = client.get("/api/v1/auth/me/")
        assert "access_status" not in resp.data["data"]

    def test_admin_response_has_no_access_status_block(self, auth_client, admin_user):
        client = auth_client(admin_user)
        resp = client.get("/api/v1/auth/me/")
        assert "access_status" not in resp.data["data"]

    def test_completed_enrollment_does_not_count_as_active(
        self, auth_client, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        EnrollmentService.complete(enrollment_id=e.id, actor=eagle, force=True)
        client = auth_client(eaglet)
        resp = client.get("/api/v1/auth/me/")
        access = resp.data["data"]["access_status"]
        assert access["has_active_program"] is False

    def test_access_status_serializable_to_json(
        self, auth_client, eaglet, nest, active_program, eagle
    ):
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        access = EnrollmentService.access_status_for(eaglet)
        # Use DRF's JSON encoder to handle datetime/UUID
        from rest_framework.utils.encoders import JSONEncoder
        json.dumps(access, cls=JSONEncoder)  # no raise

    def test_access_status_query_count_bounded(
        self, django_assert_num_queries, eaglet, nest, active_program, eagle
    ):
        """access_status_for query budget:
        2 enrollment lookups (active + pending) + 3 from compute_level
        (qualifying enrollments, level configs, points sum) = 5.
        """
        e = EnrollmentService.apply(mentee=eaglet, nest=nest)
        EnrollmentService.approve(enrollment_id=e.id, reviewer=eagle)
        with django_assert_num_queries(5):
            EnrollmentService.access_status_for(eaglet)

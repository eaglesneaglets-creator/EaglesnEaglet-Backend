"""
Tests for plan 14.6-01: legacy MentorshipRequest write path retired (410 Gone).

GET endpoints remain functional for history/audit; POST + PATCH return 410.
ProgramEnrollment flow via /enroll/ unaffected.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from apps.nests.models import Nest, MentorshipRequest
from apps.nests.models_program import Program, ProgramEnrollment

User = get_user_model()


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle.legacy@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="Legacy",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet.legacy@test.com", password="pass",
        role=User.Role.EAGLET, first_name="Eaglet", last_name="Legacy",
    )


@pytest.fixture
def nest(eagle):
    return Nest.objects.create(name="Legacy Nest", eagle=eagle)


@pytest.fixture
def active_program(nest):
    return Program.objects.create(nest=nest, name="Default", status="active")


@pytest.fixture
def auth_client():
    def _auth(user):
        c = APIClient()
        c.force_authenticate(user=user)
        return c
    return _auth


# ---------------------------------------------------------------------------
# AC-1: POST returns 410
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_post_returns_410(auth_client, eaglet, nest):
    client = auth_client(eaglet)
    before = MentorshipRequest.objects.count()
    resp = client.post(
        f"/api/v1/nests/{nest.id}/requests/",
        {"message": "Please let me in"},
        format="json",
    )
    assert resp.status_code == 410, resp.content
    body = resp.json()
    assert body["error"]["code"] == "LegacyJoinFlowRetired"
    assert "enroll" in body["error"]["migration_endpoint"]
    # No row created
    assert MentorshipRequest.objects.count() == before


# ---------------------------------------------------------------------------
# AC-2: PATCH returns 410
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_patch_returns_410(auth_client, eagle, eaglet, nest):
    # Seed a legacy pending request (simulates pre-14.6 data).
    req = MentorshipRequest.objects.create(
        nest=nest, eaglet=eaglet, message="legacy ask", status="pending",
    )
    client = auth_client(eagle)
    resp = client.patch(
        f"/api/v1/nests/{nest.id}/requests/{req.id}/",
        {"action": "approve"},
        format="json",
    )
    assert resp.status_code == 410, resp.content
    body = resp.json()
    assert body["error"]["code"] == "LegacyJoinFlowRetired"
    # Original request unchanged
    req.refresh_from_db()
    assert req.status == "pending"


# ---------------------------------------------------------------------------
# AC-3: GET endpoints remain functional
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_get_list_still_works(auth_client, eagle, eaglet, nest):
    MentorshipRequest.objects.create(
        nest=nest, eaglet=eaglet, message="legacy", status="pending",
    )
    client = auth_client(eagle)
    resp = client.get(f"/api/v1/nests/{nest.id}/requests/")
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["success"] is True
    assert len(body["data"]) >= 1


# ---------------------------------------------------------------------------
# AC-4: /enroll/ unaffected
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_enroll_endpoint_unaffected(auth_client, eaglet, nest, active_program):
    client = auth_client(eaglet)
    before = ProgramEnrollment.objects.count()
    resp = client.post(
        f"/api/v1/nests/{nest.id}/enroll/",
        {"message": "joining via new flow"},
        format="json",
    )
    assert resp.status_code in (200, 201), resp.content
    assert ProgramEnrollment.objects.count() == before + 1
    enrollment = ProgramEnrollment.objects.filter(
        mentee=eaglet, program=active_program,
    ).first()
    assert enrollment is not None
    assert enrollment.status == "pending"

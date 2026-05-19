"""
Tests for /api/v1/enums/ endpoint (plan 17-01).

Regression-safe: if anyone adds a new enum value but forgets to expose it
via core/enums.py, the group-completeness assertions catch the drift.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from apps.nests.models_program import ProgramEnrollment

User = get_user_model()


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="enums.eaglet@test.com", password="pass",
        role=User.Role.EAGLET, first_name="En", last_name="Test",
    )


@pytest.fixture
def auth_client(eaglet):
    c = APIClient()
    c.force_authenticate(user=eaglet)
    return c


@pytest.mark.django_db
def test_unauthenticated_returns_401():
    resp = APIClient().get("/api/v1/enums/")
    assert resp.status_code == 401


@pytest.mark.django_db
def test_endpoint_returns_required_keys(auth_client):
    resp = auth_client.get("/api/v1/enums/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    data = body["data"]
    required = [
        "enrollment_status", "program_status", "exit_request_status",
        "membership_status", "mentorship_request_status",
        "kyc_status", "mentee_kyc_status",
        "enrollment_status_groups", "kyc_status_groups", "mentee_kyc_status_groups",
    ]
    missing = [k for k in required if k not in data]
    assert not missing, f"Missing keys in /enums/ payload: {missing}"


@pytest.mark.django_db
def test_response_shape(auth_client):
    resp = auth_client.get("/api/v1/enums/")
    data = resp.json()["data"]
    # enrollment_status is a dict of value->label
    es = data["enrollment_status"]
    assert isinstance(es, dict)
    assert "pending" in es
    assert es["pending"] == "Pending"


@pytest.mark.django_db
def test_enrollment_status_groups_complete(auth_client):
    """Every ProgramEnrollment.Status value must live in exactly one group."""
    resp = auth_client.get("/api/v1/enums/")
    groups = resp.json()["data"]["enrollment_status_groups"]

    all_grouped = []
    for bucket, values in groups.items():
        all_grouped.extend(values)

    enum_values = [s.value for s in ProgramEnrollment.Status]

    # No duplicates across groups
    assert len(all_grouped) == len(set(all_grouped)), "Status value appears in >1 group"

    # No orphans
    orphans = set(enum_values) - set(all_grouped)
    assert not orphans, f"ProgramEnrollment.Status values not in any group: {orphans}"

    # No phantom values (group references something not in enum)
    phantoms = set(all_grouped) - set(enum_values)
    assert not phantoms, f"Groups reference non-existent enum values: {phantoms}"

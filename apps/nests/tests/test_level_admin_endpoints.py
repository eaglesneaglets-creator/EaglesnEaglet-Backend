"""
Tests for admin mentee-level CRUD endpoints (plan 14-04).

GET   /api/v1/admin/mentee-levels/   list (admin only)
PATCH /api/v1/admin/mentee-levels/   bulk update (admin only)
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from apps.nests.models_program import MenteeLevelConfig


User = get_user_model()
URL = "/api/v1/admin/mentee-levels/"


_DEFAULTS = [
    (1, "Hatchling", 0, False),
    (2, "Fledgling", 100, False),
    (3, "Flyer", 300, False),
    (4, "Soaring", 750, False),
    (5, "Master Eagle", 1500, True),
]


@pytest.fixture(autouse=True)
def _seed_levels(db):
    for level, name, pts, mentor in _DEFAULTS:
        MenteeLevelConfig.objects.update_or_create(
            level=level,
            defaults={"name": name, "points_required": pts,
                      "unlocks_mentor_application": mentor, "description": ""},
        )


@pytest.fixture
def admin_user(db):
    return User.objects.create_user(
        email="admin-l@test.com", password="pass",
        role=User.Role.ADMIN, first_name="A", last_name="D",
        is_staff=True,
    )


@pytest.fixture
def eagle_user(db):
    return User.objects.create_user(
        email="eagle-la@test.com", password="pass",
        role=User.Role.EAGLE, first_name="E", last_name="A",
    )


@pytest.fixture
def eaglet_user(db):
    return User.objects.create_user(
        email="eaglet-la@test.com", password="pass",
        role=User.Role.EAGLET, first_name="M", last_name="N",
    )


@pytest.fixture
def auth_client():
    def _c(user=None):
        c = APIClient()
        if user:
            c.force_authenticate(user=user)
        return c
    return _c


# ---------------------------------------------------------------------------
# Auth/permission guards
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_unauthenticated_rejected(auth_client):
    resp = auth_client().get(URL)
    assert resp.status_code in (401, 403)


@pytest.mark.django_db
def test_eaglet_forbidden(auth_client, eaglet_user):
    resp = auth_client(eaglet_user).get(URL)
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_eagle_forbidden(auth_client, eagle_user):
    resp = auth_client(eagle_user).get(URL)
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_admin_can_list(auth_client, admin_user):
    resp = auth_client(admin_user).get(URL)
    assert resp.status_code == status.HTTP_200_OK
    rows = resp.json()["data"]
    assert len(rows) == 5
    assert [r["level"] for r in rows] == [1, 2, 3, 4, 5]
    assert rows[4]["unlocks_mentor_application"] is True


# ---------------------------------------------------------------------------
# Bulk update happy paths
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_admin_can_bulk_update_thresholds(auth_client, admin_user):
    payload = {"levels": [
        {"level": 2, "points_required": 120, "name": "Fledgling+"},
        {"level": 3, "points_required": 350},
    ]}
    resp = auth_client(admin_user).patch(URL, payload, format="json")
    assert resp.status_code == status.HTTP_200_OK, resp.content
    l2 = MenteeLevelConfig.objects.get(level=2)
    l3 = MenteeLevelConfig.objects.get(level=3)
    assert l2.points_required == 120
    assert l2.name == "Fledgling+"
    assert l3.points_required == 350


@pytest.mark.django_db
def test_admin_update_description(auth_client, admin_user):
    payload = {"levels": [{"level": 1, "description": "Brand new mentee."}]}
    resp = auth_client(admin_user).patch(URL, payload, format="json")
    assert resp.status_code == status.HTTP_200_OK
    assert MenteeLevelConfig.objects.get(level=1).description == "Brand new mentee."


# ---------------------------------------------------------------------------
# Bulk update validation
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_rejects_non_monotonic_thresholds(auth_client, admin_user):
    payload = {"levels": [
        {"level": 3, "points_required": 50},  # below L2's 100
    ]}
    resp = auth_client(admin_user).patch(URL, payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_rejects_negative_points(auth_client, admin_user):
    payload = {"levels": [{"level": 2, "points_required": -10}]}
    resp = auth_client(admin_user).patch(URL, payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_rejects_disabling_mentor_unlock_on_level_5(auth_client, admin_user):
    payload = {"levels": [
        {"level": 5, "unlocks_mentor_application": False},
    ]}
    resp = auth_client(admin_user).patch(URL, payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_rejects_unknown_level(auth_client, admin_user):
    payload = {"levels": [{"level": 99, "points_required": 10}]}
    resp = auth_client(admin_user).patch(URL, payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_rejects_empty_payload(auth_client, admin_user):
    resp = auth_client(admin_user).patch(URL, {"levels": []}, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST

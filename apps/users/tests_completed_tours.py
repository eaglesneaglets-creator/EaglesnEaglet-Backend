"""POST /api/v1/auth/me/tours/ — server-side record of finished guided tours."""
import pytest
from rest_framework.test import APIClient

from apps.users.models import User

URL = "/api/v1/auth/me/tours/"


@pytest.fixture
def client_user(db):
    user = User.objects.create_user(email="tour@test.local", password="x", role="eaglet")
    client = APIClient()
    client.force_authenticate(user)
    return client, user


def test_requires_auth(db):
    assert APIClient().post(URL, {"tour": "eaglet-intro-v1"}, format="json").status_code == 401


def test_records_tour_once(client_user):
    client, user = client_user
    for _ in range(2):
        r = client.post(URL, {"tour": "eaglet-intro-v1"}, format="json")
        assert r.status_code == 200
    user.refresh_from_db()
    assert user.completed_tours == ["eaglet-intro-v1"]
    me = client.get("/api/v1/auth/me/").json()["data"]
    assert me["completed_tours"] == ["eaglet-intro-v1"]


@pytest.mark.parametrize("bad", ["", "Has Caps", "../x", "a" * 80, "<script>"])
def test_rejects_invalid_ids(client_user, bad):
    client, _ = client_user
    assert client.post(URL, {"tour": bad}, format="json").status_code == 400


def test_list_is_capped(client_user):
    client, user = client_user
    for i in range(60):
        client.post(URL, {"tour": f"t-{i}"}, format="json")
    user.refresh_from_db()
    assert len(user.completed_tours) == 50 and user.completed_tours[-1] == "t-59"


def test_not_writable_through_profile_patch(client_user):
    client, user = client_user
    client.patch("/api/v1/auth/me/", {"completed_tours": ["forged"]}, format="json")
    user.refresh_from_db()
    assert "forged" not in user.completed_tours

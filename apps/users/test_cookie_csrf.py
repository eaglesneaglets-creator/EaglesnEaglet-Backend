import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.models import User


@pytest.fixture
def user(db):
    return User.objects.create_user(
        email="csrf-user@test.local", password="password", role="eagle"
    )


def _csrf_client():
    return APIClient(enforce_csrf_checks=True)


@pytest.mark.django_db
def test_cookie_authenticated_mutation_requires_csrf(user):
    client = _csrf_client()
    refresh = RefreshToken.for_user(user)
    client.cookies["access_token"] = str(refresh.access_token)
    client.cookies["refresh_token"] = str(refresh)

    response = client.post("/api/v1/auth/logout/", {}, format="json")

    assert response.status_code == 403
    assert response.json()["error"]["error_code"] == "csrf_failed"


@pytest.mark.django_db
def test_csrf_token_allows_cookie_authenticated_mutation(user):
    client = _csrf_client()
    refresh = RefreshToken.for_user(user)
    client.cookies["access_token"] = str(refresh.access_token)
    client.cookies["refresh_token"] = str(refresh)
    csrf_response = client.get("/api/v1/auth/csrf/")
    csrf_token = csrf_response.json()["csrf_token"]

    response = client.post(
        "/api/v1/auth/logout/", {}, format="json", HTTP_X_CSRFTOKEN=csrf_token
    )

    assert response.status_code == 200


@pytest.mark.django_db
def test_bearer_authenticated_mutation_does_not_require_csrf(user):
    client = _csrf_client()
    access = str(RefreshToken.for_user(user).access_token)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    response = client.post("/api/v1/auth/logout/", {}, format="json")

    assert response.status_code == 200


@pytest.mark.django_db
def test_cookie_refresh_requires_csrf(user):
    client = _csrf_client()
    client.cookies["refresh_token"] = str(RefreshToken.for_user(user))

    denied = client.post("/api/v1/auth/token/refresh/", {}, format="json")
    csrf_response = client.get("/api/v1/auth/csrf/")
    allowed = client.post(
        "/api/v1/auth/token/refresh/",
        {},
        format="json",
        HTTP_X_CSRFTOKEN=csrf_response.json()["csrf_token"],
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert "refresh" not in allowed.json()

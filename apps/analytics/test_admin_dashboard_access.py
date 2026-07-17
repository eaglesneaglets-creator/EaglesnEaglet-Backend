"""Access-control tests for the admin analytics dashboard.

Regression guard for the stacked-admin 403 bug: a dual-role user granted admin
via is_platform_staff (but without Django is_staff) must be able to load the
admin dashboard.
"""

import pytest
from rest_framework_simplejwt.tokens import RefreshToken

pytestmark = pytest.mark.django_db

ADMIN_DASHBOARD_URL = "/api/v1/analytics/admin-dashboard/"


def _auth(api_client, user):
    token = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return api_client


def test_stacked_eagle_admin_can_load_dashboard(api_client, user_factory):
    """Eagle + is_platform_staff (no is_staff) — the reported bug case."""
    user = user_factory(
        email="stacked-eagle@test.com",
        role="eagle",
        is_platform_staff=True,
    )
    assert user.is_staff is False  # precondition: not a Django-staff user
    resp = _auth(api_client, user).get(ADMIN_DASHBOARD_URL)
    assert resp.status_code == 200
    assert resp.data["success"] is True


def test_stacked_eaglet_admin_can_load_dashboard(api_client, user_factory):
    """Eaglet + is_platform_staff (plan 22 dual-role mentee admin)."""
    user = user_factory(
        email="stacked-eaglet@test.com",
        role="eaglet",
        is_platform_staff=True,
    )
    resp = _auth(api_client, user).get(ADMIN_DASHBOARD_URL)
    assert resp.status_code == 200


def test_superuser_can_load_dashboard(api_client, user_factory):
    user = user_factory(
        email="super@test.com",
        role="admin",
        is_superuser=True,
        is_staff=True,
    )
    resp = _auth(api_client, user).get(ADMIN_DASHBOARD_URL)
    assert resp.status_code == 200


def test_plain_eaglet_denied_dashboard(api_client, user_factory):
    user = user_factory(email="plain-eaglet@test.com", role="eaglet")
    resp = _auth(api_client, user).get(ADMIN_DASHBOARD_URL)
    assert resp.status_code == 403

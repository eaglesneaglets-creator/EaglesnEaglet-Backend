"""Admin-settings tier control for platform configuration.

Points configuration and mentee-level config are platform settings —
superadmin-only. Scoped (dual-role) admins are denied.
"""

import pytest
from rest_framework_simplejwt.tokens import RefreshToken

pytestmark = pytest.mark.django_db

POINTS_CONFIG_URL = "/api/v1/points/config/"


def _auth(api_client, user):
    token = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return api_client


def test_scoped_admin_denied_points_config(api_client, user_factory):
    user = user_factory(email="scoped@test.com", role="eagle", is_platform_staff=True)
    resp = _auth(api_client, user).get(POINTS_CONFIG_URL)
    assert resp.status_code == 403


def test_superadmin_can_view_points_config(api_client, user_factory):
    user = user_factory(email="super@test.com", role="admin", is_superuser=True, is_staff=True)
    resp = _auth(api_client, user).get(POINTS_CONFIG_URL)
    assert resp.status_code == 200


def test_plain_eaglet_denied_points_config(api_client, user_factory):
    user = user_factory(email="mentee@test.com", role="eaglet")
    resp = _auth(api_client, user).get(POINTS_CONFIG_URL)
    assert resp.status_code == 403

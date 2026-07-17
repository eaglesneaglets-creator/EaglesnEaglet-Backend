"""Donations admin-tier access control.

Donation records/stats are financial data — superadmin only. Scoped (dual-role)
admins are denied.
"""

import pytest
from rest_framework_simplejwt.tokens import RefreshToken

pytestmark = pytest.mark.django_db

ADMIN_STATS_URL = "/api/v1/donations/admin/stats/"


def _auth(api_client, user):
    token = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return api_client


def test_scoped_admin_denied_donation_stats(api_client, user_factory):
    user = user_factory(email="scoped@test.com", role="eagle", is_platform_staff=True)
    resp = _auth(api_client, user).get(ADMIN_STATS_URL)
    assert resp.status_code == 403


def test_superadmin_can_view_donation_stats(api_client, user_factory):
    user = user_factory(email="super@test.com", role="admin", is_superuser=True, is_staff=True)
    resp = _auth(api_client, user).get(ADMIN_STATS_URL)
    assert resp.status_code == 200


def test_plain_eaglet_denied_donation_stats(api_client, user_factory):
    user = user_factory(email="mentee@test.com", role="eaglet")
    resp = _auth(api_client, user).get(ADMIN_STATS_URL)
    assert resp.status_code == 403

"""Store admin-tier access control.

Scoped admins (is_platform_staff, not superuser) manage the catalog but are
denied order management, which is superadmin-only.
"""

import pytest
from rest_framework_simplejwt.tokens import RefreshToken

pytestmark = pytest.mark.django_db

CATEGORIES_URL = "/api/v1/store/categories/"
ADMIN_ORDERS_URL = "/api/v1/store/admin/orders/"


def _auth(api_client, user):
    token = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return api_client


@pytest.fixture
def scoped_admin(user_factory):
    """Dual-role admin: platform staff, not a Django superuser."""
    return user_factory(
        email="scoped@test.com", role="eagle", is_platform_staff=True,
    )


@pytest.fixture
def superadmin(user_factory):
    return user_factory(
        email="super@test.com", role="admin", is_superuser=True, is_staff=True,
    )


def test_scoped_admin_authorized_for_catalog_create(api_client, scoped_admin):
    # Assert the scoped admin is AUTHORIZED for catalog writes — not 401/403.
    # (A 400 would just mean payload validation, which is not what we gate here.)
    resp = _auth(api_client, scoped_admin).post(
        CATEGORIES_URL, {"name": "Books", "description": "Reading"}, format="json"
    )
    assert resp.status_code not in (401, 403)


def test_scoped_admin_denied_orders(api_client, scoped_admin):
    resp = _auth(api_client, scoped_admin).get(ADMIN_ORDERS_URL)
    assert resp.status_code == 403


def test_superadmin_can_access_orders(api_client, superadmin):
    resp = _auth(api_client, superadmin).get(ADMIN_ORDERS_URL)
    assert resp.status_code == 200


def test_plain_eaglet_denied_orders(api_client, user_factory):
    user = user_factory(email="mentee@test.com", role="eaglet")
    resp = _auth(api_client, user).get(ADMIN_ORDERS_URL)
    assert resp.status_code == 403

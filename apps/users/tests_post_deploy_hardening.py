"""
Phase 26-01 — post-deployment backend hardening.

Covers the two security behaviours + the EngagementLog archival task:
- Suspended users lose API access immediately (auth-layer enforcement).
- The token-refresh endpoint is rate-limited.
- EngagementLog archival purges rows older than the retention window.
"""

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db

User = get_user_model()

ME_URL = "/api/v1/auth/me/"
REFRESH_URL = "/api/v1/auth/token/refresh/"


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    """Throttles persist counts in the cache — clear between tests."""
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def active_user():
    return User.objects.create_user(
        email="active@test.com", password="TestPassword123!",
        role=User.Role.EAGLET, first_name="Ann", last_name="Active",
        is_email_verified=True,
    )


# ---------------------------------------------------------------------------
# AC-1: suspended users lose API access immediately
# ---------------------------------------------------------------------------

def _auth_client(user):
    """Client carrying a REAL JWT (not force_authenticate).

    force_authenticate injects the user directly and BYPASSES the authentication
    layer — where the suspension check lives — so it can't test AC-1. A real
    Bearer token routes through CookieJWTAuthentication.get_user like production.
    """
    from rest_framework_simplejwt.tokens import AccessToken
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {AccessToken.for_user(user)}")
    return c


def test_active_user_can_access_api(active_user):
    assert _auth_client(active_user).get(ME_URL).status_code == 200


def test_suspended_user_is_rejected_on_authenticated_request(active_user):
    c = _auth_client(active_user)
    assert c.get(ME_URL).status_code == 200  # baseline: works while active

    # Suspend, then the very next request must be rejected — no waiting for
    # the access token to expire. Enforced at the auth layer.
    active_user.status = User.Status.SUSPENDED
    active_user.save(update_fields=["status"])

    resp = c.get(ME_URL)
    assert resp.status_code == 403


def test_suspended_response_carries_machine_readable_code(active_user):
    """403 + error_code 'account_suspended' so the client can route to the
    /suspended page instead of treating it as an expired session (401), which
    would trigger a pointless refresh loop."""
    c = _auth_client(active_user)
    active_user.status = User.Status.SUSPENDED
    active_user.save(update_fields=["status"])

    resp = c.get(ME_URL)
    assert resp.status_code == 403
    body = resp.json()
    assert body["success"] is False
    assert body["error"]["error_code"] == "account_suspended"
    assert "suspended" in body["error"]["message"].lower()


def test_isnotsuspended_permission_allows_anonymous():
    """IsNotSuspended must PASS for anonymous callers so AllowAny endpoints
    (login/register/refresh) still work."""
    from core.permissions import IsNotSuspended
    from types import SimpleNamespace

    anon = SimpleNamespace(is_authenticated=False)
    req = SimpleNamespace(user=anon)
    assert IsNotSuspended().has_permission(req, view=None) is True


# ---------------------------------------------------------------------------
# AC-2: token refresh is rate-limited
# ---------------------------------------------------------------------------

def test_refresh_endpoint_is_throttled():
    c = APIClient()
    # No valid refresh cookie → each call returns 401, but the THROTTLE counts
    # every attempt. After the 20/min limit, further calls return 429.
    statuses = [c.post(REFRESH_URL, {}).status_code for _ in range(25)]
    assert 429 in statuses, f"expected a 429 within 25 rapid refreshes, got {set(statuses)}"


# ---------------------------------------------------------------------------
# AC-4: EngagementLog archival purges old rows
# ---------------------------------------------------------------------------

def test_engagement_log_archival_purges_old_rows(active_user):
    from apps.analytics.models import EngagementLog
    from apps.analytics.tasks import archive_engagement_logs

    old = EngagementLog.objects.create(user=active_user, action="login")
    recent = EngagementLog.objects.create(user=active_user, action="login")
    # Backdate the "old" row past the 90-day window (created_at is auto_now_add).
    EngagementLog.objects.filter(pk=old.pk).update(
        created_at=timezone.now() - timedelta(days=120)
    )

    deleted = archive_engagement_logs()

    assert not EngagementLog.objects.filter(pk=old.pk).exists()
    assert EngagementLog.objects.filter(pk=recent.pk).exists()
    assert deleted >= 1

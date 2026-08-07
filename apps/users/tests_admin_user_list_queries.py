"""Query-count guard for the admin user list.

Measured before the fix: **63 queries** for a 20-row page — 39 of them the same
`SELECT ... FROM mentee_kyc`. Two independent causes, both needed fixing:

1. `AdminUserListView` used a bare `User.objects.all()`. The serializer exposes
   `User.avatar_url`, whose fallback chain reaches for `mentor_kyc`/`mentee_kyc`
   (Phase 32-01), so each row triggered a lookup.

2. `UserSerializer.get_kyc_status` guarded the cached relation with `hasattr`.
   A reverse one-to-one accessor raises `RelatedObjectDoesNotExist` when no row
   exists, so `hasattr` is False both when the relation was never fetched AND
   when it was fetched and is genuinely empty. Users without KYC — the majority —
   fell through and re-queried to confirm the absence, once each, forever.

After both fixes: **3 queries**, independent of page size.

These tests pin the query count so a future change can't quietly reintroduce
either cause. They deliberately use a fixed cap while varying row count: if the
count scales with rows, the cap is breached and the N+1 is back.
"""
import pytest
from rest_framework_simplejwt.tokens import AccessToken

from apps.users.models import User, MenteeKYC


# A cap comfortably above the measured 3 (auth, count, page) but far below
# anything that scales per row.
MAX_QUERIES = 12


def _admin_client(client):
    admin = User.objects.create_user(
        email="qguard-admin@test.local", password="x", first_name="Q", last_name="Guard",
        role="admin", is_staff=True, is_superuser=True,
    )
    client.cookies["access_token"] = str(AccessToken.for_user(admin))
    return client


def _make_eaglets(n, with_kyc=False):
    made = []
    for i in range(n):
        u = User.objects.create_user(
            email=f"qguard-eaglet{i}@test.local", password="x",
            first_name=f"E{i}", last_name="Test", role="eaglet",
        )
        if with_kyc:
            MenteeKYC.objects.create(user=u, status="approved")
        made.append(u)
    return made


@pytest.mark.django_db
def test_admin_user_list_query_count_does_not_scale_with_rows(client, django_assert_max_num_queries):
    """20 users must cost the same as 5 — that is what 'no N+1' means."""
    _make_eaglets(20)
    c = _admin_client(client)

    with django_assert_max_num_queries(MAX_QUERIES):
        resp = c.get("/api/v1/auth/admin/users/?per_page=100")

    assert resp.status_code == 200
    assert len(resp.json()["data"]["users"]) >= 20


@pytest.mark.django_db
def test_users_without_kyc_do_not_each_trigger_a_lookup(client, django_assert_max_num_queries):
    """The exact regression: `hasattr` on an absent reverse one-to-one.

    Every user here lacks a KYC row, which is the case the old code re-queried
    for. Before the fix this cost one extra query per user.
    """
    _make_eaglets(15, with_kyc=False)
    c = _admin_client(client)

    with django_assert_max_num_queries(MAX_QUERIES):
        resp = c.get("/api/v1/auth/admin/users/?per_page=100")

    assert resp.status_code == 200
    # All of them must report no KYC — the fast path must be correct, not just fast.
    rows = [r for r in resp.json()["data"]["users"] if r["email"].startswith("qguard-eaglet")]
    assert rows, "test users missing from response"
    assert all(r["kyc_status"] is None for r in rows)


@pytest.mark.django_db
def test_kyc_status_still_correct_when_relation_is_populated(client):
    """Guards the other half: the optimisation must not blank out real data.

    A cache-aware fast path that returns None for everyone would pass the query
    -count tests above while breaking the feature.
    """
    _make_eaglets(3, with_kyc=True)
    c = _admin_client(client)

    resp = c.get("/api/v1/auth/admin/users/?per_page=100")
    assert resp.status_code == 200

    rows = [r for r in resp.json()["data"]["users"] if r["email"].startswith("qguard-eaglet")]
    assert len(rows) == 3
    assert all(r["kyc_status"] == "approved" for r in rows), [r["kyc_status"] for r in rows]


@pytest.mark.django_db
def test_soft_deleted_users_are_excluded_from_admin_list_and_total(client):
    """Anonymized accounts remain in the database, but not user management."""
    visible_user = _make_eaglets(1)[0]
    deleted_user = User.objects.create_user(
        email="qguard-deleted@test.local",
        password="x",
        first_name="Deleted",
        last_name="User",
        role="eaglet",
    )
    deleted_user.soft_delete()
    c = _admin_client(client)

    response = c.get("/api/v1/auth/admin/users/?per_page=100")

    assert response.status_code == 200
    payload = response.json()["data"]
    returned_ids = {row["id"] for row in payload["users"]}
    assert str(visible_user.id) in returned_ids
    assert str(deleted_user.id) not in returned_ids
    assert payload["pagination"]["total"] == len(payload["users"])

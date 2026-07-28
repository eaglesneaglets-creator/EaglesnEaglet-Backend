"""
Tests for admin nest oversight (Phase 27-01).

Coverage:
- list all nests + filters + superadmin-only (403 for non-super)
- nest detail
- NestActivity recording on join / post / content / admin actions
- create-on-behalf: happy + reject non-eagle + reject unapproved-KYC
- archive
- remove-member
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from apps.nests.models import Nest, NestMembership, NestPost, NestResource
from apps.nests.models_activity import NestActivity
from apps.users.models import MentorKYC

User = get_user_model()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def superadmin(db):
    return User.objects.create_user(
        email="super@test.com", password="p", role=User.Role.ADMIN,
        first_name="Super", last_name="Admin", is_staff=True, is_superuser=True,
    )


@pytest.fixture
def plain_admin(db):
    return User.objects.create_user(
        email="admin@test.com", password="p", role=User.Role.ADMIN,
        first_name="Plain", last_name="Admin", is_staff=True,
    )


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@test.com", password="p", role=User.Role.EAGLE,
        first_name="Daniel", last_name="Oppong",
    )


@pytest.fixture
def approved_eagle(db):
    """An eagle with approved KYC. The KYC→approved signal auto-creates a nest."""
    e = User.objects.create_user(
        email="approved@test.com", password="p", role=User.Role.EAGLE,
        first_name="Approved", last_name="Mentor",
    )
    kyc = MentorKYC.objects.create(user=e, status="draft")
    kyc.status = "approved"
    kyc.save()
    return e


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com", password="p", role=User.Role.EAGLET,
        first_name="Sarah", last_name="Jenkins",
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(
        eagle=eagle, name="Faith & Profession",
        description="Integrating christian values into modern workplace.",
        category=Nest.Category.FAITH,
    )


@pytest.fixture
def super_client(superadmin):
    c = APIClient()
    c.force_authenticate(superadmin)
    return c


# ---------------------------------------------------------------------------
# AC-1: list + filters + permission
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_superadmin_lists_all_nests(super_client, nest):
    resp = super_client.get("/api/v1/admin/nests/")
    assert resp.status_code == 200
    data = resp.json()["data"]
    ids = [n["id"] for n in data]
    assert str(nest.id) in ids
    row = next(n for n in data if n["id"] == str(nest.id))
    assert row["category"] == "faith"
    assert row["eagle"]["full_name"] == "Daniel Oppong"
    assert "member_count" in row and "status" in row


@pytest.mark.django_db
def test_category_and_search_filters(super_client, nest, eagle):
    Nest.objects.create(eagle=eagle, name="Youth Leadership", category=Nest.Category.LEADERSHIP)
    faith = super_client.get("/api/v1/admin/nests/?category=faith").json()["data"]
    assert all(n["category"] == "faith" for n in faith)
    found = super_client.get("/api/v1/admin/nests/?search=Youth").json()["data"]
    assert any("Youth" in n["name"] for n in found)


@pytest.mark.django_db
def test_non_superadmin_forbidden(plain_admin, eaglet, nest):
    for user in (plain_admin, eaglet):
        c = APIClient()
        c.force_authenticate(user)
        assert c.get("/api/v1/admin/nests/").status_code == 403


# ---------------------------------------------------------------------------
# AC-2: detail
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_nest_detail_includes_members_content_activity(super_client, nest, eaglet):
    NestMembership.objects.create(nest=nest, user=eaglet, status="active")
    NestResource.objects.create(nest=nest, title="Ethics.pdf", file_url="https://x/y.pdf", uploaded_by=nest.eagle)
    resp = super_client.get(f"/api/v1/admin/nests/{nest.id}/")
    assert resp.status_code == 200
    d = resp.json()["data"]
    assert any(m["user"]["full_name"] == "Sarah Jenkins" for m in d["members"])
    assert any(c["title"] == "Ethics.pdf" for c in d["shared_content"])
    assert "recent_activity" in d


# ---------------------------------------------------------------------------
# AC-3: activity recording via signals
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_activity_recorded_on_join_post_content(super_client, nest, eaglet):
    NestMembership.objects.create(nest=nest, user=eaglet, status="active")
    NestPost.objects.create(nest=nest, author=nest.eagle, content="Welcome!")
    NestResource.objects.create(nest=nest, title="Slides.pdf", file_url="https://x/s.pdf", uploaded_by=nest.eagle)

    types = set(NestActivity.objects.filter(nest=nest).values_list("action_type", flat=True))
    assert "member_joined" in types
    assert "post_created" in types
    assert "content_shared" in types

    resp = super_client.get(f"/api/v1/admin/nests/{nest.id}/activity/")
    assert resp.status_code == 200
    assert len(resp.json()["data"]) >= 3


# ---------------------------------------------------------------------------
# AC-4: create-on-behalf
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_create_on_behalf_happy(super_client, approved_eagle):
    payload = {
        "name": "Marriage Preparation", "description": "For engaged couples.",
        "category": "relationships", "privacy": "public", "max_members": 4,
        "eagle_id": str(approved_eagle.id),
    }
    resp = super_client.post("/api/v1/admin/nests/", payload, format="json")
    assert resp.status_code == 201, resp.content
    d = resp.json()["data"]
    assert d["eagle"]["id"] == str(approved_eagle.id)
    assert d["category"] == "relationships"
    # Activity row records the admin as actor.
    nest = Nest.objects.get(pk=d["id"])
    assert NestActivity.objects.filter(nest=nest, action_type="nest_created").exists()


@pytest.mark.django_db
def test_create_on_behalf_rejects_non_eagle(super_client, eaglet):
    payload = {"name": "X", "eagle_id": str(eaglet.id)}
    resp = super_client.post("/api/v1/admin/nests/", payload, format="json")
    assert resp.status_code == 400


@pytest.mark.django_db
def test_create_on_behalf_rejects_unapproved_kyc(super_client, eagle):
    # `eagle` has no approved MentorKYC.
    payload = {"name": "X", "eagle_id": str(eagle.id)}
    resp = super_client.post("/api/v1/admin/nests/", payload, format="json")
    assert resp.status_code == 400
    assert "KYC" in str(resp.content) or "kyc" in str(resp.content).lower()


# ---------------------------------------------------------------------------
# AC-5: archive + remove member
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_archive_nest(super_client, nest):
    resp = super_client.patch(f"/api/v1/admin/nests/{nest.id}/archive/")
    assert resp.status_code == 200
    nest.refresh_from_db()
    assert nest.is_active is False
    assert NestActivity.objects.filter(nest=nest, action_type="nest_archived").exists()
    # Archived nest no longer appears in the default (non-archived) list.
    listing = super_client.get("/api/v1/admin/nests/").json()["data"]
    assert str(nest.id) not in [n["id"] for n in listing]


@pytest.mark.django_db
def test_remove_member(super_client, nest, eaglet):
    m = NestMembership.objects.create(nest=nest, user=eaglet, status="active")
    resp = super_client.delete(f"/api/v1/admin/nests/{nest.id}/members/{m.id}/")
    assert resp.status_code == 200
    m.refresh_from_db()
    assert m.status == "removed"
    assert NestActivity.objects.filter(nest=nest, action_type="member_removed").exists()


@pytest.mark.django_db
def test_cannot_remove_nest_owner(super_client, nest):
    owner_m = NestMembership.objects.create(nest=nest, user=nest.eagle, status="active")
    resp = super_client.delete(f"/api/v1/admin/nests/{nest.id}/members/{owner_m.id}/")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Shared Content aggregation (bug fix): resource library + post attachments +
# inline links — not just NestResource.
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_shared_content_merges_resources_attachments_and_links(super_client, nest):
    # 1) formal resource-library upload
    NestResource.objects.create(
        nest=nest, title="Ethics.pdf", file_url="https://cdn/ethics.pdf",
        uploaded_by=nest.eagle,
    )
    # 2) a post carrying a file attachment
    NestPost.objects.create(
        nest=nest, author=nest.eagle, content="Morning devotion notes",
        attachment_url="https://cdn/notes.png", attachment_type="image",
    )
    # 3) a post with an inline link in the body
    NestPost.objects.create(
        nest=nest, author=nest.eagle,
        content="Great read here https://example.com/article on stewardship",
    )

    resp = super_client.get(f"/api/v1/admin/nests/{nest.id}/")
    assert resp.status_code == 200
    content = resp.json()["data"]["shared_content"]
    kinds = {c["kind"] for c in content}
    assert kinds == {"resource", "attachment", "link"}

    by_url = {c["url"]: c for c in content}
    assert by_url["https://cdn/ethics.pdf"]["kind"] == "resource"
    assert by_url["https://cdn/notes.png"]["kind"] == "attachment"
    assert by_url["https://example.com/article"]["kind"] == "link"
    # unified shape present on every row
    for c in content:
        assert set(c) >= {"kind", "title", "url", "content_type", "shared_by", "created_at"}


@pytest.mark.django_db
def test_shared_content_empty_when_nothing_shared(super_client, nest):
    resp = super_client.get(f"/api/v1/admin/nests/{nest.id}/")
    assert resp.json()["data"]["shared_content"] == []


# ---------------------------------------------------------------------------
# Backfill command (bug fix): reconstruct history + idempotent re-run.
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_backfill_reconstructs_activity_and_is_idempotent(nest, eaglet):
    from django.core.management import call_command

    NestMembership.objects.create(nest=nest, user=eaglet, status="active")
    NestPost.objects.create(nest=nest, author=nest.eagle, content="Welcome all")
    NestResource.objects.create(
        nest=nest, title="Slides.pdf", file_url="https://cdn/s.pdf", uploaded_by=nest.eagle,
    )
    # Simulate PRE-27-01 history: wipe the signal-created audit rows so this
    # nest looks like one whose activity was never recorded.
    NestActivity.objects.filter(nest=nest).delete()
    assert NestActivity.objects.filter(nest=nest).count() == 0

    # Backfill reconstructs all three from the surviving source rows.
    call_command("backfill_nest_activity", "--nest", str(nest.id))
    after_first = NestActivity.objects.filter(nest=nest).count()
    assert after_first == 3
    assert NestActivity.objects.filter(nest=nest, action_type="member_joined").exists()
    assert NestActivity.objects.filter(nest=nest, action_type="post_created").exists()
    assert NestActivity.objects.filter(nest=nest, action_type="content_shared").exists()

    # Re-run: source_ref dedup → no duplicates.
    call_command("backfill_nest_activity", "--nest", str(nest.id))
    assert NestActivity.objects.filter(nest=nest).count() == 3


@pytest.mark.django_db
def test_backfill_does_not_double_log_signal_recorded_rows(nest, eaglet):
    """When signals ALREADY recorded a post/resource (post-27-01 data), backfill
    must not add a second copy — the time-window dedup catches signal rows that
    lack a source_ref."""
    from django.core.management import call_command

    NestPost.objects.create(nest=nest, author=nest.eagle, content="Recent post")
    NestResource.objects.create(
        nest=nest, title="Recent.pdf", file_url="https://cdn/r.pdf", uploaded_by=nest.eagle,
    )
    # Signals fired → 1 post_created + 1 content_shared already exist.
    assert NestActivity.objects.filter(nest=nest, action_type="post_created").count() == 1
    assert NestActivity.objects.filter(nest=nest, action_type="content_shared").count() == 1

    call_command("backfill_nest_activity", "--nest", str(nest.id))

    # Still exactly one of each — no double-log.
    assert NestActivity.objects.filter(nest=nest, action_type="post_created").count() == 1
    assert NestActivity.objects.filter(nest=nest, action_type="content_shared").count() == 1

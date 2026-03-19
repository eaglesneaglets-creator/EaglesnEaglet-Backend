"""Tests for social features: likes, comment replies, media upload."""

import pytest
from django.contrib.auth import get_user_model

from apps.nests.models import Nest, NestPost, NestPostComment

User = get_user_model()


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="Test",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com", password="pass",
        role=User.Role.EAGLET, first_name="Eaglet", last_name="Test",
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="Test Nest", eagle=eagle)


@pytest.fixture
def post(db, nest, eagle):
    return NestPost.objects.create(nest=nest, author=eagle, content="Hello world")


@pytest.fixture
def top_comment(db, post, eaglet):
    return NestPostComment.objects.create(post=post, author=eaglet, content="Top level")


def test_comment_parent_field_is_nullable(db, post, eaglet):
    """NestPostComment.parent defaults to None for top-level comments."""
    comment = NestPostComment.objects.create(post=post, author=eaglet, content="Top")
    assert comment.parent is None


def test_comment_can_have_parent(db, top_comment, eagle):
    """A reply references another comment as its parent."""
    reply = NestPostComment.objects.create(
        post=top_comment.post, author=eagle,
        content="Reply text", parent=top_comment,
    )
    assert reply.parent == top_comment
    assert list(top_comment.replies.all()) == [reply]


from django.db import IntegrityError
from apps.nests.models import NestPostLike


def test_postlike_can_be_created(db, post, eaglet):
    """A user can like a post."""
    like = NestPostLike.objects.create(post=post, user=eaglet)
    assert like.post == post
    assert like.user == eaglet


def test_postlike_unique_per_user_per_post(db, post, eaglet):
    """A user cannot like the same post twice."""
    NestPostLike.objects.create(post=post, user=eaglet)
    with pytest.raises(IntegrityError):
        NestPostLike.objects.create(post=post, user=eaglet)


from django.db.models import Prefetch
from rest_framework.exceptions import ValidationError
from apps.nests.services import CommunityService


def test_toggle_like_creates_like_and_increments_count(db, post, eaglet):
    """First toggle_like creates a like and bumps likes_count."""
    result = CommunityService.toggle_like(str(post.id), eaglet)
    post.refresh_from_db()
    assert result["liked"] is True
    assert result["likes_count"] == 1
    assert post.likes_count == 1


def test_toggle_like_removes_like_and_decrements_count(db, post, eaglet):
    """Second toggle_like removes the like and decrements likes_count."""
    CommunityService.toggle_like(str(post.id), eaglet)
    result = CommunityService.toggle_like(str(post.id), eaglet)
    post.refresh_from_db()
    assert result["liked"] is False
    assert result["likes_count"] == 0
    assert post.likes_count == 0


def test_get_comments_returns_only_top_level(db, post, eagle, eaglet, top_comment):
    """get_comments excludes replies (parent is not None)."""
    NestPostComment.objects.create(
        post=post, author=eagle, content="Reply", parent=top_comment
    )
    comments = list(CommunityService.get_comments(str(post.id)))
    assert len(comments) == 1
    assert comments[0].id == top_comment.id


def test_get_comments_prefetches_replies(db, post, eagle, eaglet, top_comment):
    """get_comments prefetches replies so accessing them triggers no extra queries."""
    from django.test.utils import CaptureQueriesContext
    from django.db import connection

    NestPostComment.objects.create(
        post=post, author=eagle, content="Reply", parent=top_comment
    )
    comments = list(CommunityService.get_comments(str(post.id)))
    with CaptureQueriesContext(connection) as ctx:
        replies = list(comments[0].replies.all())
    assert len(replies) == 1
    assert len(ctx) == 0, f"Expected 0 queries (prefetched), got {len(ctx)}"


def test_add_reply_creates_reply(db, top_comment, eagle):
    """add_reply creates a NestPostComment with parent set."""
    reply = CommunityService.add_reply(str(top_comment.id), eagle, "My reply")
    assert reply.parent == top_comment
    assert reply.author == eagle
    assert reply.content == "My reply"


def test_add_reply_prevents_nested_threading(db, top_comment, eagle, eaglet):
    """add_reply raises ValidationError when target is itself a reply."""
    reply = CommunityService.add_reply(str(top_comment.id), eagle, "First reply")
    with pytest.raises(ValidationError):
        CommunityService.add_reply(str(reply.id), eaglet, "Should not work")


from rest_framework.test import APIClient
from apps.nests.models import NestMembership


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def member(db, nest, eaglet):
    NestMembership.objects.create(nest=nest, user=eaglet)
    return eaglet


def test_like_endpoint_toggles(db, api_client, nest, post, member):
    """POST /nests/{nest_pk}/posts/{pk}/like/ toggles like."""
    api_client.force_authenticate(user=member)
    url = f"/api/v1/nests/{nest.id}/posts/{post.id}/like/"
    r = api_client.post(url)
    assert r.status_code == 200
    assert r.data["liked"] is True
    assert r.data["likes_count"] == 1
    r2 = api_client.post(url)
    assert r2.data["liked"] is False
    assert r2.data["likes_count"] == 0


def test_comment_list_endpoint_returns_top_level_with_replies(
    db, api_client, nest, post, member, top_comment, eagle
):
    """GET /nests/{pk}/posts/{pk}/comment-list/ returns top-level comments with replies."""
    NestPostComment.objects.create(
        post=post, author=eagle, content="Reply", parent=top_comment
    )
    api_client.force_authenticate(user=member)
    r = api_client.get(f"/api/v1/nests/{nest.id}/posts/{post.id}/comment-list/")
    assert r.status_code == 200
    assert len(r.data) == 1
    assert len(r.data[0]["replies"]) == 1


def test_add_reply_endpoint(db, api_client, nest, post, member, top_comment):
    """POST /nests/{nest_pk}/posts/{pk}/comments/{comment_pk}/replies/ adds a reply."""
    api_client.force_authenticate(user=member)
    url = f"/api/v1/nests/{nest.id}/posts/{post.id}/comments/{top_comment.id}/replies/"
    r = api_client.post(url, {"content": "My reply"}, format="json")
    assert r.status_code == 201
    assert r.data["data"]["content"] == "My reply"

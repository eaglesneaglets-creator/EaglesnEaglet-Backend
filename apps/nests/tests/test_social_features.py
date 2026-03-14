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

"""Tests for post like/comment notification signals."""

import pytest
from django.contrib.auth import get_user_model

from apps.notifications.models import Notification

User = get_user_model()


def test_post_like_notification_type_exists():
    """Notification.NotificationType.POST_LIKE must be defined."""
    assert hasattr(Notification.NotificationType, 'POST_LIKE')
    assert Notification.NotificationType.POST_LIKE == 'post_like'


def test_post_comment_notification_type_exists():
    """Notification.NotificationType.POST_COMMENT must be defined."""
    assert hasattr(Notification.NotificationType, 'POST_COMMENT')
    assert Notification.NotificationType.POST_COMMENT == 'post_comment'


from apps.nests.models import Nest, NestPost, NestPostComment, NestPostLike


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@notif.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="T",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@notif.com", password="pass",
        role=User.Role.EAGLET, first_name="Eaglet", last_name="T",
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="Signal Test Nest", eagle=eagle)


@pytest.fixture
def post(db, nest, eagle):
    return NestPost.objects.create(nest=nest, author=eagle, content="Test post")


def test_like_creates_notification_for_post_author(db, post, eaglet):
    """Liking a post notifies the post author."""
    NestPostLike.objects.create(post=post, user=eaglet)
    notif = Notification.objects.filter(
        recipient=post.author,
        notification_type=Notification.NotificationType.POST_LIKE,
    ).first()
    assert notif is not None
    assert eaglet.first_name in notif.message


def test_like_does_not_notify_self(db, post, eagle):
    """Liking your own post does not create a notification."""
    NestPostLike.objects.create(post=post, user=eagle)
    count = Notification.objects.filter(
        recipient=eagle,
        notification_type=Notification.NotificationType.POST_LIKE,
    ).count()
    assert count == 0


def test_comment_creates_notification_for_post_author(db, post, eaglet):
    """Commenting on a post notifies the post author."""
    NestPostComment.objects.create(post=post, author=eaglet, content="Great post!")
    notif = Notification.objects.filter(
        recipient=post.author,
        notification_type=Notification.NotificationType.POST_COMMENT,
    ).first()
    assert notif is not None
    assert eaglet.first_name in notif.message


def test_comment_action_url_uses_correct_role_prefix(db, post, eaglet):
    """action_url uses /eagle/ for Eagle authors."""
    NestPostComment.objects.create(post=post, author=eaglet, content="Test")
    notif = Notification.objects.get(
        recipient=post.author,
        notification_type=Notification.NotificationType.POST_COMMENT,
    )
    # post.author is an Eagle
    assert notif.action_url.startswith("/eagle/")


def test_reply_does_not_send_duplicate_notification(db, post, eaglet, eagle):
    """Self-notification excluded: eagle replies to eaglet's comment on eagle's post."""
    top = NestPostComment.objects.create(post=post, author=eaglet, content="Top level")
    NestPostComment.objects.create(post=post, author=eagle, content="Reply", parent=top)
    # eaglet commented → eagle (post author) gets notified (1 notification)
    # eagle replied → eagle is the post author, self-notification excluded
    count = Notification.objects.filter(
        notification_type=Notification.NotificationType.POST_COMMENT,
    ).count()
    assert count == 1

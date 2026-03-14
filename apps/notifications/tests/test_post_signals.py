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

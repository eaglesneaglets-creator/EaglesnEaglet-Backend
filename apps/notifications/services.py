"""
Notification Services

Business logic for creating and managing notifications.
"""

import logging

from .models import Notification

logger = logging.getLogger(__name__)


class NotificationService:
    """Handles notification creation and management."""

    @staticmethod
    def create_notification(
        recipient,
        notification_type: str,
        title: str,
        message: str,
        action_url: str = "",
    ) -> Notification:
        """Create an in-app notification for a user."""
        notification = Notification.objects.create(
            recipient=recipient,
            notification_type=notification_type,
            title=title,
            message=message,
            action_url=action_url,
        )
        logger.info(
            "Notification created: %s → %s", notification_type, recipient.email
        )
        return notification

    @staticmethod
    def get_user_notifications(user, unread_only: bool = False):
        """Get notifications for a user."""
        qs = Notification.objects.filter(recipient=user)
        if unread_only:
            qs = qs.filter(is_read=False)
        return qs

    @staticmethod
    def get_unread_count(user) -> int:
        """Get count of unread notifications."""
        return Notification.objects.filter(recipient=user, is_read=False).count()

    @staticmethod
    def mark_as_read(user, notification_id: str) -> bool:
        """Mark a single notification as read."""
        updated = Notification.objects.filter(
            id=notification_id, recipient=user, is_read=False
        ).update(is_read=True)
        return updated > 0

    @staticmethod
    def mark_all_as_read(user) -> int:
        """Mark all unread notifications as read. Returns count updated."""
        return Notification.objects.filter(
            recipient=user, is_read=False
        ).update(is_read=True)

"""
Notification Services

Business logic for creating and managing notifications.
"""

import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import transaction

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
        """
        Create an in-app notification for a user.

        Registers a post-commit hook to push the notification via WebSocket.
        Using on_commit avoids RuntimeError when this method is called from within
        a Channels consumer or inside a select_for_update() block.
        """
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

        # Defer WS push to post-commit so we don't call into the event loop
        # mid-transaction (would cause RuntimeError or deadlock on PostgreSQL).
        transaction.on_commit(
            lambda: async_to_sync(NotificationService.push_to_websocket)(notification)
        )

        return notification

    @staticmethod
    async def push_to_websocket(notification: Notification) -> None:
        """
        Push a notification to the user's WebSocket channel group.
        Called post-commit via async_to_sync(push_to_websocket)(notification).
        """
        channel_layer = get_channel_layer()
        if channel_layer is None:
            logger.warning("push_to_websocket: no channel layer configured — skipping WS push")
            return

        group_name = f"notifications_{notification.recipient_id}"
        payload = {
            "type": "notification_message",
            "data": {
                "id": str(notification.id),
                "notification_type": notification.notification_type,
                "title": notification.title,
                "message": notification.message,
                "action_url": notification.action_url,
                "is_read": notification.is_read,
                "created_at": notification.created_at.isoformat() if notification.created_at else None,
            },
        }
        try:
            await channel_layer.group_send(group_name, payload)
            logger.debug("WS push sent: %s → group %s", notification.notification_type, group_name)
        except Exception as exc:
            # WS push failure is non-critical — notification is already saved in DB
            logger.error("WS push failed for notification %s: %s", notification.id, exc)

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

"""Tests for WebSocket push on notification creation."""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from apps.users.models import User
from apps.notifications.models import Notification
from apps.notifications.services import NotificationService


@pytest.fixture
def user(db):
    return User.objects.create_user(
        email="wsuser@test.com", password="pass123",
        first_name="WS", last_name="User",
        role="eaglet", is_email_verified=True,
    )


class TestPushToWebSocket:
    def test_push_to_websocket_sends_to_group(self, user):
        """push_to_websocket calls channel_layer.group_send with correct data."""
        notification = Notification(
            id="00000000-0000-0000-0000-000000000001",
            recipient=user,
            notification_type="general",
            title="Test",
            message="Test message",
            action_url="/test",
        )
        mock_channel_layer = AsyncMock()
        mock_channel_layer.group_send = AsyncMock()

        with patch("apps.notifications.services.get_channel_layer", return_value=mock_channel_layer):
            from asgiref.sync import async_to_sync
            async_to_sync(NotificationService.push_to_websocket)(notification)

        mock_channel_layer.group_send.assert_called_once()
        call_args = mock_channel_layer.group_send.call_args
        group_name = call_args[0][0]
        payload = call_args[0][1]
        assert group_name == f"notifications_{user.id}"
        assert payload["type"] == "notification_message"
        assert payload["data"]["title"] == "Test"
        assert payload["data"]["message"] == "Test message"

    def test_create_notification_triggers_push_on_commit(self, user, db):
        """create_notification registers a post-commit hook for WS push."""
        with patch("apps.notifications.services.transaction") as mock_tx:
            mock_tx.on_commit = MagicMock()
            NotificationService.create_notification(
                recipient=user,
                notification_type="general",
                title="Test",
                message="Hello",
            )
        # on_commit should have been called once with a lambda
        mock_tx.on_commit.assert_called_once()

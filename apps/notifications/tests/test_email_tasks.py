"""Tests for notification Celery tasks."""
import smtplib
import pytest
from unittest.mock import patch, MagicMock

from apps.users.models import User


@pytest.fixture
def user(db):
    return User.objects.create_user(
        email="user@test.com", password="pass123",
        first_name="Test", last_name="User",
        role="eaglet", is_email_verified=True,
    )


class TestSendEmailNotification:
    def test_sends_email_with_correct_subject(self, user):
        from apps.notifications.tasks import send_email_notification
        with patch("apps.notifications.tasks.render_to_string", return_value="<html>test</html>"):
            with patch("apps.notifications.tasks.send_mail") as mock_send:
                send_email_notification(
                    recipient_id=str(user.id),
                    subject="Test Subject",
                    template_name="emails/points_awarded.html",
                    context={"points": 50, "description": "Great work"},
                )
                assert mock_send.called
                call_args = mock_send.call_args
                assert call_args[1]["subject"] == "Test Subject" or call_args[0][0] == "Test Subject"

    def test_skips_when_user_not_found(self, db):
        from apps.notifications.tasks import send_email_notification
        with patch("apps.notifications.tasks.send_mail") as mock_send:
            # Non-existent user ID — should not raise, should log warning
            send_email_notification(
                recipient_id="00000000-0000-0000-0000-000000000000",
                subject="Test",
                template_name="emails/points_awarded.html",
                context={},
            )
            assert not mock_send.called

    def test_retries_on_smtp_failure(self, user):
        """Task calls self.retry() when SMTP raises — after max_retries, raises Retry exception."""
        from apps.notifications.tasks import send_email_notification
        # Simulate max retries already reached — task raises Retry which becomes MaxRetriesExceededError
        with patch("apps.notifications.tasks.send_mail", side_effect=smtplib.SMTPException("SMTP down")):
            with pytest.raises(Exception):  # Celery raises Retry or MaxRetriesExceededError
                send_email_notification.apply(
                    kwargs=dict(
                        recipient_id=str(user.id),
                        subject="Test",
                        template_name="emails/points_awarded.html",
                        context={"points": 10, "description": "test"},
                    ),
                    retries=send_email_notification.max_retries,  # exhausted
                ).get()


class TestSendPointsAwardedEmail:
    def test_dispatches_send_email_task(self, user):
        from apps.notifications.tasks import send_points_awarded_email
        with patch("apps.notifications.tasks.send_email_notification") as mock_task:
            send_points_awarded_email(
                user_id=str(user.id),
                points=100,
                description="Excellent work",
            )
            assert mock_task.called
            call_str = str(mock_task.call_args)
            assert str(user.id) in call_str
            assert "100" in call_str


class TestSendOrderConfirmedEmail:
    def test_dispatches_send_email_task(self, user):
        from apps.notifications.tasks import send_order_confirmed_email
        with patch("apps.notifications.tasks.send_email_notification") as mock_task:
            send_order_confirmed_email(
                user_id=str(user.id),
                order_id="abc-123",
            )
            assert mock_task.called
            call_str = str(mock_task.call_args)
            assert str(user.id) in call_str

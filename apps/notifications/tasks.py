"""
Notification Celery Tasks

Async email delivery with retry logic.
Tasks are auto-discovered by Celery (see eaglesneagletsbackend/celery.py).

NOTE: In local development, CELERY_TASK_ALWAYS_EAGER=True so tasks
run synchronously. In test, set CELERY_TASK_ALWAYS_EAGER=False.
"""

import logging

from celery import shared_task
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_email_notification(self, recipient_id: str, subject: str, template_name: str, context: dict):
    """
    Base email task. Renders an HTML template and sends via Django's email backend.
    Retries up to 3 times on SMTP failure (60s between retries).
    """
    import smtplib
    from apps.users.models import User

    try:
        user = User.objects.get(id=recipient_id)
    except User.DoesNotExist:
        logger.warning("send_email_notification: user %s not found — skipping", recipient_id)
        return

    context.setdefault("user", user)
    context.setdefault("frontend_url", getattr(settings, "FRONTEND_URL", "http://localhost:5173"))

    try:
        html_message = render_to_string(template_name, context)
        send_mail(
            subject=subject,
            message="",  # plain text body (empty — HTML-only email)
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info("Email sent: %s → %s", subject, user.email)
    except smtplib.SMTPException as exc:
        logger.error("SMTP error sending to %s: %s — retrying", user.email, exc)
        raise self.retry(exc=exc)
    except Exception as exc:
        logger.error("Unexpected error sending email to %s: %s", user.email, exc)
        raise


@shared_task
def send_points_awarded_email(user_id: str, points: int, description: str):
    """Notify a user that they were awarded points."""
    send_email_notification(
        recipient_id=user_id,
        subject="You earned points!",
        template_name="emails/points_awarded.html",
        context={"points": points, "description": description},
    )


@shared_task
def send_order_confirmed_email(user_id: str, order_id: str):
    """Notify a user that their order was confirmed."""
    send_email_notification(
        recipient_id=user_id,
        subject="Your order is confirmed!",
        template_name="emails/order_confirmed.html",
        context={"order_id": order_id},
    )

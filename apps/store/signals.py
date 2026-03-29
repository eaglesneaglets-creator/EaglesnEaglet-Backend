"""
Store Signals

Fires post-save notifications when new orders are created.
Notifies all active admin users via in-app (WebSocket) + email.
"""

import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)


@receiver(post_save, sender="store.Order")
def notify_admins_on_new_order(sender, instance, created, **kwargs):
    """
    When a new Order is created, notify all active admin users:
    - In-app notification (WebSocket via NotificationService)
    - Email via Celery task
    """
    if not created:
        return

    from apps.users.models import User
    from apps.notifications.services import NotificationService
    from apps.notifications.tasks import send_email_notification

    customer_name = (
        f"{instance.user.first_name} {instance.user.last_name}".strip()
        if instance.user_id
        else (instance.guest_name or "Guest")
    )
    customer_email = instance.user.email if instance.user_id else (instance.guest_email or "")
    order_short = str(instance.id)[:8].upper()

    admins = User.objects.filter(role="admin", is_active=True)
    for admin in admins:
        try:
            NotificationService.create_notification(
                recipient=admin,
                notification_type="general",
                title="New order received",
                message=f"Order #{order_short} from {customer_name} — ₵{instance.total_amount}",
                action_url="/admin/store/orders",
            )
            send_email_notification.delay(
                str(admin.id),
                f"New Order #{order_short} Received",
                "emails/new_order_admin.html",
                {
                    "order_id": str(instance.id),
                    "order_short": order_short,
                    "customer_name": customer_name,
                    "customer_email": customer_email,
                    "total_amount": str(instance.total_amount),
                    "item_count": instance.items.count(),
                    "created_at": instance.created_at.isoformat() if instance.created_at else "",
                },
            )
        except Exception:
            logger.exception("Failed to notify admin %s of new order %s", admin.id, instance.id)

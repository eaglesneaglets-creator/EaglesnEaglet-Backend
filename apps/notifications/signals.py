"""
Notification Signals

Automatically create notifications when:
- A mentorship request is created (notify Eagle)
- A mentorship request is approved/rejected (notify Eaglet)
- Points are awarded (notify user)
"""

import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.nests.models import MentorshipRequest
from apps.points.models import PointTransaction

from .models import Notification
from .services import NotificationService

logger = logging.getLogger(__name__)


@receiver(post_save, sender=MentorshipRequest)
def notify_on_mentorship_request(sender, instance, created, **kwargs):
    """Notify Eagle when a new mentorship request arrives, or
    notify Eaglet when their request is approved/rejected."""

    if created:
        # New request → notify the Eagle (nest owner)
        eagle = instance.nest.eagle
        NotificationService.create_notification(
            recipient=eagle,
            notification_type="mentorship_request",
            title="New Mentorship Request",
            message=f"{instance.eaglet.first_name} {instance.eaglet.last_name} wants to join your Nest \"{instance.nest.name}\".",
            action_url=f"/nest/{instance.nest.id}/settings",
        )
    else:
        # Status changed → notify the Eaglet
        if instance.status == "approved":
            NotificationService.create_notification(
                recipient=instance.eaglet,
                notification_type="mentorship_approved",
                title="Request Approved!",
                message=f"Your request to join \"{instance.nest.name}\" has been approved. Welcome!",
                action_url=f"/nest/{instance.nest.id}",
            )
        elif instance.status == "rejected":
            NotificationService.create_notification(
                recipient=instance.eaglet,
                notification_type="mentorship_rejected",
                title="Request Declined",
                message=f"Your request to join \"{instance.nest.name}\" was not approved.",
                action_url="/nests/browse",
            )


@receiver(post_save, sender=PointTransaction)
def notify_on_points_awarded(sender, instance, created, **kwargs):
    """Notify user when they earn points."""
    if not created:
        return

    NotificationService.create_notification(
        recipient=instance.user,
        notification_type="points_awarded",
        title=f"+{instance.points} Points!",
        message=instance.description or f"You earned {instance.points} points.",
        action_url="/points",
    )


@receiver(post_save, sender="nests.NestPostLike")
def notify_on_post_like(sender, instance, created, **kwargs):
    """Notify a post author when someone likes their post."""
    if not created:
        return
    author = instance.post.author
    if author == instance.user:
        return  # Don't notify yourself
    nest_prefix = "eagle" if author.role == author.Role.EAGLE else "eaglet"
    NotificationService.create_notification(
        recipient=author,
        notification_type=Notification.NotificationType.POST_LIKE,
        title="Someone liked your post",
        message=f"{instance.user.first_name} liked your post.",
        action_url=f"/{nest_prefix}/nest/{instance.post.nest_id}",
    )


@receiver(post_save, sender="nests.NestPostComment")
def notify_on_post_comment(sender, instance, created, **kwargs):
    """Notify a post author when someone comments on their post."""
    if not created:
        return
    author = instance.post.author
    if author == instance.author:
        return  # Don't notify yourself
    nest_prefix = "eagle" if author.role == author.Role.EAGLE else "eaglet"
    NotificationService.create_notification(
        recipient=author,
        notification_type=Notification.NotificationType.POST_COMMENT,
        title="New comment on your post",
        message=f"{instance.author.first_name} commented on your post.",
        action_url=f"/{nest_prefix}/nest/{instance.post.nest_id}",
    )

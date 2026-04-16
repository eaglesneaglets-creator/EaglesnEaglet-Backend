"""
Donation Signals

Awards points to authenticated donors after a successful donation.
"""

import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Donation

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Donation)
def award_points_on_donation(sender, instance: Donation, created: bool, **kwargs):
    """
    Award 10 points to authenticated donors when their donation succeeds.

    Only fires when:
    - The donation is saved with status SUCCESS (not on creation, which is PENDING)
    - The donor is an authenticated user (not an anonymous donation)

    Uses update_fields guard to avoid infinite signal loops — only triggers
    when 'status' is in the fields being saved.
    """
    update_fields = kwargs.get("update_fields")

    # Skip on initial creation (status is PENDING at creation)
    if created:
        return

    # Only process when the status field is being updated
    if update_fields and "status" not in update_fields:
        return

    if instance.status != Donation.Status.SUCCESS:
        return

    if not instance.donor_id:
        return

    try:
        from apps.points.services import PointsService

        PointsService.award_points(
            user=instance.donor,
            points=10,
            activity_type="donation",
            reference_id=str(instance.id),
        )
        logger.info(
            "Awarded 10 points to user %s for donation %s",
            instance.donor_id,
            instance.id,
        )
    except Exception:
        # Points failure must NOT roll back the donation — log and continue
        logger.exception(
            "Failed to award points for donation %s (user %s)",
            instance.id,
            instance.donor_id,
        )

"""
Signals for the users app (plan 14.5-01).

Auto-create a Nest for an Eagle the moment their MentorKYC is approved,
so mentors land on the dashboard with a Nest container ready and only need
to manually create the Program inside it.
"""

import logging

from django.db import transaction
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .models import MentorKYC

logger = logging.getLogger(__name__)


_PREVIOUS_STATUS_ATTR = "_previous_kyc_status"


@receiver(pre_save, sender=MentorKYC)
def capture_previous_status(sender, instance: MentorKYC, **kwargs):
    """Stash prior status so post_save can detect approval transitions."""
    if instance.pk is None:
        setattr(instance, _PREVIOUS_STATUS_ATTR, None)
        return
    try:
        prior = MentorKYC.objects.only("status").get(pk=instance.pk)
        setattr(instance, _PREVIOUS_STATUS_ATTR, prior.status)
    except MentorKYC.DoesNotExist:
        setattr(instance, _PREVIOUS_STATUS_ATTR, None)


@receiver(post_save, sender=MentorKYC)
def auto_create_nest_on_approval(sender, instance: MentorKYC, created: bool, **kwargs):
    """Create one Nest per Eagle on first approval transition. Idempotent."""
    if instance.status != "approved":
        return

    previous = getattr(instance, _PREVIOUS_STATUS_ATTR, None)
    # Fire only when status actually transitions to 'approved'.
    # If previous is unknown (created=True or pre_save not seen), still allow
    # — get_or_create keeps it idempotent.
    if previous == "approved":
        return

    user = instance.user
    if user is None or getattr(user, "role", None) != "eagle":
        return

    def _create_nest():
        # Local import avoids circular dependency at app boot.
        from apps.nests.models import Nest

        first_name = (user.first_name or user.email.split("@")[0]).strip()
        nest_name = f"{first_name}'s Nest"
        nest, was_created = Nest.objects.get_or_create(
            eagle=user,
            defaults={"name": nest_name},
        )
        if was_created:
            logger.info(
                "Auto-created Nest=%s for newly-approved Eagle=%s",
                nest.id, user.id,
            )
        else:
            logger.debug(
                "Eagle=%s already had Nest=%s; skipping auto-create",
                user.id, nest.id,
            )

    transaction.on_commit(_create_nest)

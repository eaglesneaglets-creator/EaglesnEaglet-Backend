"""
Signals for the nests app (plan 14-02).

Mirror ProgramEnrollment status onto NestMembership so existing community
features (posts, events, comments) keep working without knowing about programs:

  - PENDING / REJECTED              → no membership
  - ACTIVE                          → ACTIVE membership (create or flip)
  - COMPLETED / RELEASED / OPTED_OUT → INACTIVE (read-only access; chat send +
                                       post create endpoints check this in 14-03)
"""

import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import NestMembership
from .models_program import ProgramEnrollment

logger = logging.getLogger(__name__)


@receiver(post_save, sender=ProgramEnrollment)
def sync_nest_membership(sender, instance: ProgramEnrollment, **kwargs):
    """Mirror enrollment status onto NestMembership."""
    nest = instance.program.nest
    user = instance.mentee

    if instance.status == ProgramEnrollment.Status.ACTIVE:
        membership, created = NestMembership.objects.get_or_create(
            nest=nest, user=user,
            defaults={
                "role": NestMembership.MemberRole.MEMBER,
                "status": NestMembership.Status.ACTIVE,
            },
        )
        if not created and membership.status != NestMembership.Status.ACTIVE:
            membership.status = NestMembership.Status.ACTIVE
            membership.save(update_fields=["status"])
        logger.info("NestMembership ACTIVE for enrollment=%s", instance.id)
        return

    if instance.status in {
        ProgramEnrollment.Status.COMPLETED,
        ProgramEnrollment.Status.RELEASED,
        ProgramEnrollment.Status.OPTED_OUT,
    }:
        membership = NestMembership.objects.filter(nest=nest, user=user).first()
        if membership and membership.status == NestMembership.Status.ACTIVE:
            membership.status = NestMembership.Status.INACTIVE
            membership.save(update_fields=["status"])
            logger.info(
                "NestMembership INACTIVE for enrollment=%s (read-only)",
                instance.id,
            )
        return

    # PENDING and REJECTED — no membership side-effect.

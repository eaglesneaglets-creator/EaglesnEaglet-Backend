"""
Admin Role Management signals (plan 18-01).

Today's only behaviour: when an admin's account is deactivated
(``is_active`` flips True → False), automatically drop their
``is_platform_staff`` flag and log a ``system_revoked`` audit entry. This
ensures elevated privileges never coexist with a suspended account.
"""

from __future__ import annotations

import logging

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .models import User
from .models_admin import AdminRoleAudit

logger = logging.getLogger(__name__)

_PREV_IS_ACTIVE = "_admin_role_prev_is_active"


@receiver(pre_save, sender=User)
def _capture_prev_is_active(sender, instance: User, **kwargs):
    if instance.pk is None:
        setattr(instance, _PREV_IS_ACTIVE, None)
        return
    try:
        prior = User.objects.only("is_active", "is_platform_staff").get(pk=instance.pk)
        setattr(instance, _PREV_IS_ACTIVE, prior.is_active)
    except User.DoesNotExist:
        setattr(instance, _PREV_IS_ACTIVE, None)


@receiver(post_save, sender=User)
def _auto_revoke_on_suspend(sender, instance: User, created: bool, **kwargs):
    if created:
        return
    prev = getattr(instance, _PREV_IS_ACTIVE, None)
    if prev is None:
        return
    transitioned_to_inactive = prev is True and instance.is_active is False
    if not transitioned_to_inactive:
        return
    if not instance.is_platform_staff:
        return

    # Drop the flag.
    User.objects.filter(pk=instance.pk).update(is_platform_staff=False)
    # Mutate the in-memory instance too so any downstream listeners see fresh state.
    instance.is_platform_staff = False

    # Audit entry.
    AdminRoleAudit.objects.create(
        actor=None,
        target=instance,
        action=AdminRoleAudit.Action.SYSTEM_REVOKED,
        source=AdminRoleAudit.Source.SYSTEM,
        reason="Account deactivated — platform admin privileges auto-revoked.",
    )
    logger.info(
        "admin-role: auto-revoked is_platform_staff for user=%s on suspend",
        instance.pk,
    )

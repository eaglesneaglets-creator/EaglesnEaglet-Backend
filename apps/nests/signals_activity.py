"""
Nest activity signals (Phase 27-01).

Populate the NestActivity audit trail on the events an admin cares about:
member joins/leaves, content shared, posts created. Admin-initiated events
(nest created / archived / member removed) are recorded directly from the
service layer where the acting admin is known — not here.

Kept separate from signals.py (which mirrors ProgramEnrollment → membership)
so the two concerns don't tangle.
"""

import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import NestMembership, NestPost, NestResource
from .models_activity import NestActivity

logger = logging.getLogger(__name__)


def record_activity(nest, actor, action_type, target="", **metadata):
    """Cheap single-INSERT audit helper. Never raises into the caller."""
    try:
        NestActivity.objects.create(
            nest=nest,
            actor=actor,
            action_type=action_type,
            target=target or "",
            metadata=metadata or {},
        )
    except Exception as exc:  # pragma: no cover - audit must never break flow
        logger.warning("Failed to record NestActivity (%s): %s", action_type, exc)


@receiver(post_save, sender=NestMembership)
def on_membership_saved(sender, instance: NestMembership, created, **kwargs):
    """Record joins (create as active) and leaves (flip to inactive/removed).

    Member REMOVAL initiated by an admin is recorded in the service layer with
    the acting admin as actor; here we only capture the organic join/leave so
    we don't double-log. We detect admin-removal by the presence of a
    `_skip_activity_signal` flag set on the instance by the service.
    """
    if getattr(instance, "_skip_activity_signal", False):
        return

    name = getattr(instance.user, "full_name", None) or str(instance.user)

    if created and instance.status == NestMembership.Status.ACTIVE:
        record_activity(
            instance.nest, instance.user,
            NestActivity.ActionType.MEMBER_JOINED, target=name,
        )
        return

    if not created and instance.status in {
        NestMembership.Status.INACTIVE,
        NestMembership.Status.REMOVED,
    }:
        record_activity(
            instance.nest, instance.user,
            NestActivity.ActionType.MEMBER_LEFT, target=name,
        )


@receiver(post_save, sender=NestPost)
def on_post_created(sender, instance: NestPost, created, **kwargs):
    if not created:
        return
    author = getattr(instance.author, "full_name", None) or str(instance.author)
    record_activity(
        instance.nest, instance.author,
        NestActivity.ActionType.POST_CREATED,
        target=(instance.content or "")[:80],
        author=author,
    )


@receiver(post_save, sender=NestResource)
def on_resource_shared(sender, instance: NestResource, created, **kwargs):
    if not created:
        return
    uploader = getattr(instance.uploaded_by, "full_name", None) or str(instance.uploaded_by)
    record_activity(
        instance.nest, instance.uploaded_by,
        NestActivity.ActionType.CONTENT_SHARED,
        target=instance.title,
        uploaded_by=uploader,
    )

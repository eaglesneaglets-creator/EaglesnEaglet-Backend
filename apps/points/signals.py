"""
Points Signals

Post-save signals that:
1. Award points when content is completed or assignments are submitted.
2. Trigger one-time badge awards on key user actions.

Sender strings use the full app name (e.g. "apps.nests.NestMembership")
because INSTALLED_APPS registers apps as "apps.nests", "apps.content", etc.
Using short labels (e.g. "nests.NestMembership") would silently never fire.
"""

import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.content.models import ContentProgress, AssignmentSubmission

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Existing point-awarding signals
# ---------------------------------------------------------------------------

@receiver(post_save, sender=ContentProgress)
def award_points_on_content_completion(sender, instance, **kwargs):
    """Award points when a content item is marked as completed."""
    if instance.status != "completed":
        return

    from .services import PointService

    activity_map = {
        "video": "video_complete",
        "document": "document_read",
        "reading": "document_read",
    }

    content_item = instance.content_item
    activity_type = activity_map.get(content_item.content_type, "document_read")
    nest = content_item.module.nest

    PointService.award_points(
        user=instance.user,
        activity_type=activity_type,
        source_id=content_item.id,
        nest=nest,
        description=f"Completed: {content_item.title}",
        override_points=content_item.points_value or None,
    )

    # Check if entire module is now complete
    from apps.content.services import ProgressService

    module = content_item.module
    completion = ProgressService.get_module_completion_percentage(
        instance.user, module.id
    )
    if completion >= 100.0:
        PointService.award_points(
            user=instance.user,
            activity_type="module_complete",
            source_id=module.id,
            nest=nest,
            description=f"Module completed: {module.title}",
            override_points=module.points_value or None,
        )

    # Invalidate dashboard stats cache
    from apps.analytics.services import AnalyticsService
    AnalyticsService.clear_dashboard_cache(instance.user.id, instance.user.role)


@receiver(post_save, sender=AssignmentSubmission)
def award_points_on_assignment_submission(sender, instance, created, **kwargs):
    """Award points when an assignment is submitted."""
    if not created:
        return

    from .services import PointService

    assignment = instance.assignment
    # Standalone assignments have nest directly; module-based ones go through module.
    nest = assignment.nest if assignment.nest else (
        assignment.module.nest if assignment.module else None
    )
    if not nest:
        logger.warning("Assignment %s has no nest — skipping points award.", assignment.id)
        return

    PointService.award_points(
        user=instance.user,
        activity_type="assignment_submit",
        source_id=instance.id,
        nest=nest,
        description=f"Assignment submitted: {assignment.title}",
        override_points=assignment.points_value or None,
    )

    # Clear cached stats
    from apps.analytics.services import AnalyticsService
    AnalyticsService.clear_dashboard_cache(instance.user.id, instance.user.role)


# ---------------------------------------------------------------------------
# One-time badge signals
# NOTE: sender strings use "app_label.ModelName" format (two parts).
# Django resolves these using the app_label from AppConfig, which is the
# short label (e.g. "users", "nests", "content", "points") — NOT the full
# module path like "apps.users".
# ---------------------------------------------------------------------------

def _is_eaglet(user) -> bool:
    """Return True only for Eaglet (mentee) users."""
    return getattr(user, 'role', None) == 'eaglet'


@receiver(post_save, sender="users.UserProfile")
def on_profile_completed(sender, instance, created, **kwargs):
    """Award 'Egg Cracker' when an Eaglet's profile is first created."""
    if not created:
        return
    if not _is_eaglet(instance.user):
        return
    from apps.points.services import PointService
    PointService.award_one_time_badge(instance.user, "egg_cracker")


@receiver(post_save, sender="nests.NestMembership")
def on_nest_membership_active(sender, instance, created, **kwargs):
    """Award 'Found My Nest' when an Eaglet joins their first active nest."""
    if not created:
        return
    if instance.status != "active":
        return
    if not _is_eaglet(instance.user):
        return
    from apps.points.services import PointService
    PointService.award_one_time_badge(instance.user, "first_nest_join")


@receiver(post_save, sender="nests.NestResource")
def on_first_resource_shared(sender, instance, created, **kwargs):
    """Award 'Resource Eagle' on first resource upload (Eagle action — no role filter)."""
    if not created:
        return
    from apps.points.services import PointService
    PointService.award_one_time_badge(instance.uploaded_by, "first_resource_share")


@receiver(post_save, sender="points.PointTransaction")
def on_manual_point_received(sender, instance, created, **kwargs):
    """Award 'Mentor's Mark' when an Eaglet receives their first manual award."""
    if not created:
        return
    from apps.points.models import PointTransaction
    if instance.source != PointTransaction.Source.MANUAL:
        return
    if not _is_eaglet(instance.user):
        return
    from apps.points.services import PointService
    PointService.award_one_time_badge(instance.user, "mentors_mark")


@receiver(post_save, sender="content.AssignmentSubmission")
def on_early_assignment_submit(sender, instance, created, **kwargs):
    """Award 'Early Bird' when an Eaglet submits before due date."""
    if not created:
        return
    if not _is_eaglet(instance.user):
        return
    assignment = instance.assignment
    if not assignment.due_date:
        logger.debug("early_bird badge skipped: assignment %s has no due date", assignment.id)
    elif instance.submitted_at < assignment.due_date:
        from apps.points.services import PointService
        PointService.award_one_time_badge(instance.user, "early_bird")


@receiver(post_save, sender="content.ModuleAssignmentAttempt")
def on_perfect_quiz_score(sender, instance, created, **kwargs):
    """Award 'Perfect Feathers' when an Eaglet scores 100% on a quiz."""
    if not created:
        return
    if instance.score != 100:
        return
    if not _is_eaglet(instance.user):
        return
    from apps.points.services import PointService
    PointService.award_one_time_badge(instance.user, "perfect_feathers")

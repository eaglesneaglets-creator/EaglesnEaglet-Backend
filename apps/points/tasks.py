"""
Points Celery Tasks

Badge evaluation is offloaded here so that award_points() returns
immediately without blocking on 8+ DB queries.
"""

import logging
from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def check_and_award_badges_async(self, user_id):
    """
    Run badge evaluation for a user in the background.

    Called by PointService.award_points() after every point transaction.
    Failures here do NOT affect the point award (already committed).
    """
    try:
        from apps.users.models import User
        from .services import PointService

        user = User.objects.get(id=user_id)
        PointService.check_and_award_badges(user)

    except Exception as exc:
        logger.warning(
            "Badge evaluation failed for user %s (attempt %d): %s",
            user_id, self.request.retries + 1, exc,
        )
        raise self.retry(exc=exc, countdown=30 * (2 ** self.request.retries))

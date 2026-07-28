"""
Analytics maintenance tasks (Phase 26-01).

EngagementLog is an append-only firehose (one row per user action) that powers
dashboard aggregates. Raw rows lose value once aggregated, so this task purges
rows past the retention window to keep the table — and backups/queries — lean.
"""

import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(name='analytics.archive_engagement_logs')
def archive_engagement_logs():
    """Delete EngagementLog rows older than the retention window.

    Retention is settings.ENGAGEMENT_LOG_RETENTION_DAYS (default 90). Returns
    the number of rows deleted. Runs weekly via Celery beat.
    """
    from .models import EngagementLog

    retention_days = getattr(settings, 'ENGAGEMENT_LOG_RETENTION_DAYS', 90)
    cutoff = timezone.now() - timedelta(days=retention_days)

    old_rows = EngagementLog.objects.filter(created_at__lt=cutoff)
    deleted_count = old_rows.count()
    old_rows.delete()

    logger.info(
        "EngagementLog archival: purged %d rows older than %d days.",
        deleted_count, retention_days,
    )
    return deleted_count

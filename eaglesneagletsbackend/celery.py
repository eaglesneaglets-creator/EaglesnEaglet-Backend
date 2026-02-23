"""
Celery Configuration for Eagles & Eaglets

Celery is used for running background tasks like:
- Sending emails
- Processing file uploads
- Calculating points
- Generating reports
- Scheduled tasks (daily reports, cleanup jobs)
"""

import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eaglesneagletsbackend.settings')

# Create Celery app
app = Celery('eaglesneagletsbackend')

# Load config from Django settings
# All celery-related settings should be prefixed with CELERY_
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks in all installed apps
# Celery will look for a tasks.py file in each app
app.autodiscover_tasks()

# =============================================================================
# CELERY BEAT SCHEDULE (Periodic Tasks)
# =============================================================================
# Tasks that run on a schedule (like cron jobs)
app.conf.beat_schedule = {
    # Example: Clean up expired sessions every day at midnight
    # 'cleanup-expired-sessions': {
    #     'task': 'apps.users.tasks.cleanup_expired_sessions',
    #     'schedule': crontab(hour=0, minute=0),
    # },

    # Example: Send daily digest emails every morning at 8 AM
    # 'send-daily-digest': {
    #     'task': 'apps.notifications.tasks.send_daily_digest',
    #     'schedule': crontab(hour=8, minute=0),
    # },

    # Example: Calculate weekly points every Sunday at midnight
    # 'calculate-weekly-points': {
    #     'task': 'apps.points.tasks.calculate_weekly_points',
    #     'schedule': crontab(hour=0, minute=0, day_of_week=0),
    # },
}


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """A simple debug task for testing Celery."""
    print(f'Request: {self.request!r}')

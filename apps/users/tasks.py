"""
User Celery Tasks

Asynchronous tasks for email sending and other background operations.
"""

import gzip
import logging
import os
import subprocess
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .constants import EMAIL_SUBJECTS

logger = logging.getLogger(__name__)


def _frontend_url():
    """Return FRONTEND_URL from settings, never localhost in production."""
    return settings.FRONTEND_URL


def _support_email():
    """Return support email from settings with fallback."""
    return getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com')


def _send_templated_email(task, user_id, email_name, template, subject_key,
                          context_builder, skip_check=None, subject_fallback=None):
    """
    Shared helper that handles the fetch-user → render → send → retry pattern.

    Args:
        task: The bound Celery task instance (self).
        user_id: UUID of the user.
        email_name: Human-readable label for logging (e.g. "verification").
        template: Django template path (e.g. 'emails/verify_email.html').
        subject_key: Key into EMAIL_SUBJECTS dict.
        context_builder: Callable(user, frontend_url) → dict of extra template context.
        skip_check: Optional callable(user) → bool. If truthy, skip sending.
        subject_fallback: Fallback subject string when subject_key is missing.
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        if skip_check and skip_check(user):
            logger.info(f"User {user.email} — skipping {email_name} email")
            return

        extra_context = context_builder(user, _frontend_url())
        context = {
            'user': user,
            'support_email': _support_email(),
            **extra_context,
        }

        html_message = render_to_string(template, context)
        plain_message = strip_tags(html_message)

        subject = EMAIL_SUBJECTS.get(subject_key, subject_fallback) if subject_fallback else EMAIL_SUBJECTS[subject_key]

        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"{email_name.capitalize()} email sent to {user.email}")

    except SoftTimeLimitExceeded:
        logger.error("%s email task timed out for user %s — aborting.", email_name.capitalize(), user_id)
        return
    except User.DoesNotExist:
        logger.warning("%s email skipped — user %s no longer exists.", email_name.capitalize(), user_id)
        return
    except Exception as exc:
        logger.error("Failed to send %s email to user %s (attempt %d): %s",
                     email_name, user_id, task.request.retries + 1, exc)
        raise task.retry(exc=exc, countdown=60 * (2 ** task.request.retries))


# ---------------------------------------------------------------------------
# Individual email tasks — each one is thin: just wires up context_builder
# ---------------------------------------------------------------------------

@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_verification_email(self, user_id, raw_token):
    """Send email verification email to user.

    raw_token is the plaintext token returned by generate_email_verification_token().
    The DB stores only its SHA-256 hash, so the raw value must be passed explicitly.
    """
    _send_templated_email(
        self, user_id,
        email_name="verification",
        template='emails/verify_email.html',
        subject_key='verification',
        skip_check=lambda u: u.is_email_verified,
        context_builder=lambda u, url: {
            'verification_url': f"{url}/verify-email?token={raw_token}",
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_password_reset_email(self, user_id, raw_token):
    """Send password reset email to user.

    raw_token is the plaintext token returned by generate_password_reset_token().
    The DB stores only its SHA-256 hash, so the raw value must be passed explicitly.
    """
    _send_templated_email(
        self, user_id,
        email_name="password reset",
        template='emails/password_reset.html',
        subject_key='password_reset',
        context_builder=lambda u, url: {
            'reset_url': f"{url}/reset-password?token={raw_token}",
            'expiry_minutes': 15,
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_kyc_submitted_email(self, user_id):
    """Send KYC submission confirmation email to mentor."""
    _send_templated_email(
        self, user_id,
        email_name="KYC submitted",
        template='emails/kyc_submitted.html',
        subject_key='kyc_submitted',
        context_builder=lambda u, url: {
            'status_url': f"{url}/kyc/pending",
            'review_days': '2-3',
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_kyc_approved_email(self, user_id):
    """Send KYC approval email to mentor."""
    _send_templated_email(
        self, user_id,
        email_name="KYC approved",
        template='emails/kyc_approved.html',
        subject_key='kyc_approved',
        context_builder=lambda u, url: {
            'dashboard_url': f"{url}/login",
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_kyc_rejected_email(self, user_id, rejection_reason):
    """Send KYC rejection email to mentor."""
    _send_templated_email(
        self, user_id,
        email_name="KYC rejected",
        template='emails/kyc_rejected.html',
        subject_key='kyc_rejected',
        context_builder=lambda u, url: {
            'kyc_url': f"{url}/kyc",
            'rejection_reason': rejection_reason,
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_welcome_email(self, user_id):
    """Send welcome email after successful email verification."""
    _send_templated_email(
        self, user_id,
        email_name="welcome",
        template='emails/welcome.html',
        subject_key='welcome',
        context_builder=lambda u, url: {
            'login_url': f"{url}/login",
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_eaglet_welcome_email(self, user_id):
    """Send welcome email to eaglet after completing onboarding."""
    _send_templated_email(
        self, user_id,
        email_name="eaglet welcome",
        template='emails/eaglet_welcome.html',
        subject_key='eaglet_welcome',
        context_builder=lambda u, url: {
            'dashboard_url': f"{url}/login",
            'explore_url': f"{url}/explore",
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_kyc_changes_requested_email(self, user_id, review_notes):
    """Send email to mentor when changes are requested on their KYC application."""
    _send_templated_email(
        self, user_id,
        email_name="KYC changes requested",
        template='emails/kyc_changes_requested.html',
        subject_key='kyc_changes_requested',
        subject_fallback='Action Required: Update Your Mentor Application',
        context_builder=lambda u, url: {
            'kyc_url': f"{url}/kyc",
            'review_notes': review_notes,
        },
    )


# =============================================================================
# MAINTENANCE TASKS
# =============================================================================

@shared_task(name='users.cleanup_expired_sessions')
def cleanup_expired_sessions():
    """
    Delete expired UserSession rows (Celery beat — runs daily).

    Removes:
    - Sessions where expires_at is in the past
    - Inactive sessions older than 30 days (belt-and-suspenders)

    Prevents the user_sessions table from growing unboundedly.
    """
    from django.utils import timezone
    from datetime import timedelta
    from .models import UserSession

    now = timezone.now()
    cutoff = now - timedelta(days=30)

    expired = UserSession.objects.filter(expires_at__lt=now)
    stale_inactive = UserSession.objects.filter(is_active=False, created_at__lt=cutoff)

    expired_count = expired.count()
    stale_count = stale_inactive.count()

    expired.delete()
    stale_inactive.delete()

    logger.info(
        "Session cleanup: deleted %d expired + %d stale inactive sessions.",
        expired_count, stale_count,
    )


# =============================================================================
# PROFILE TASKS (For both Mentor and Mentee KYC)
# =============================================================================

@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_profile_submitted_email(self, user_id, role):
    """Send profile submission confirmation email to user (mentor or mentee)."""
    from django.utils import timezone

    def _context(u, url):
        return {
            'role': role,
            'frontend_url': url,
            'submitted_at': timezone.now(),
        }

    _send_templated_email(
        self, user_id,
        email_name=f"profile submitted ({role})",
        template='emails/profile_submitted.html',
        subject_key='profile_submitted',
        subject_fallback='Your Profile is Under Review',
        context_builder=_context,
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_profile_approved_email(self, user_id, role):
    """Send profile approval email to user (mentor or mentee)."""
    template = 'emails/mentor_approved.html' if role == 'mentor' else 'emails/mentee_approved.html'
    subject_key = 'mentor_approved' if role == 'mentor' else 'mentee_approved'

    _send_templated_email(
        self, user_id,
        email_name=f"profile approved ({role})",
        template=template,
        subject_key=subject_key,
        subject_fallback=f'Congratulations! Your {role.title()} Profile is Approved',
        context_builder=lambda u, url: {
            'dashboard_url': f"{url}/dashboard",
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_profile_rejected_email(self, user_id, role, rejection_reason):
    """Send profile rejection email to user (mentor or mentee)."""
    _send_templated_email(
        self, user_id,
        email_name=f"profile rejected ({role})",
        template='emails/profile_rejected.html',
        subject_key='profile_rejected',
        subject_fallback='Update Required: Your Profile Application',
        context_builder=lambda u, url: {
            'role': role,
            'rejection_reason': rejection_reason,
        },
    )


@shared_task(bind=True, max_retries=3, soft_time_limit=60, time_limit=90)
def send_profile_changes_requested_email(self, user_id, role, review_notes):
    """Send email when changes are requested on a profile (mentor or mentee)."""
    _send_templated_email(
        self, user_id,
        email_name=f"profile changes requested ({role})",
        template='emails/profile_changes_requested.html',
        subject_key='profile_changes_requested',
        subject_fallback='Action Required: Please Update Your Profile',
        context_builder=lambda u, url: {
            'role': role,
            'profile_url': f"{url}/complete-profile",
            'review_notes': review_notes,
        },
    )


# =============================================================================
# C8 — DATABASE BACKUP TASK
# =============================================================================

@shared_task(name='users.backup_database')
def backup_database():
    """
    Create a gzip-compressed pg_dump backup of the primary database.

    - Stores backups under BASE_DIR/backups/db_backup_<timestamp>.sql.gz
    - Retains the 7 most recent backups; older files are deleted automatically
    - Scheduled daily at 02:00 UTC via CELERY_BEAT_SCHEDULE

    Credentials are read from settings.DATABASES['default'] so no extra
    configuration is needed beyond the standard Django DB settings.
    """
    from datetime import datetime, timezone as dt_timezone
    from pathlib import Path

    db = settings.DATABASES['default']
    backup_dir = Path(settings.BASE_DIR) / 'backups'
    backup_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(dt_timezone.utc).strftime('%Y%m%d_%H%M%S')
    output_path = backup_dir / f"db_backup_{timestamp}.sql.gz"

    cmd = [
        'pg_dump',
        '--host', db.get('HOST', 'localhost'),
        '--port', str(db.get('PORT', 5432)),
        '--username', db['USER'],
        '--no-password',
        '--format', 'plain',
        db['NAME'],
    ]

    env = {**os.environ, 'PGPASSWORD': db.get('PASSWORD', '')}

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            env=env,
        )

        if result.returncode != 0:
            logger.error(
                "backup_database: pg_dump exited %d — %s",
                result.returncode,
                result.stderr.decode(errors='replace'),
            )
            return

        with gzip.open(output_path, 'wb') as f:
            f.write(result.stdout)

        size_kb = output_path.stat().st_size // 1024
        logger.info("backup_database: created %s (%d KB)", output_path.name, size_kb)

        # Rotate — keep only the 7 most recent backups
        backups = sorted(backup_dir.glob('db_backup_*.sql.gz'))
        for old in backups[:-7]:
            old.unlink()
            logger.info("backup_database: removed old backup %s", old.name)

    except FileNotFoundError:
        logger.error(
            "backup_database: pg_dump not found — ensure postgresql-client is installed."
        )
    except Exception as exc:
        logger.error("backup_database: unexpected error — %s", exc)

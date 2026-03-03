"""
User Celery Tasks

Asynchronous tasks for email sending and other background operations.
"""

import logging
from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .constants import EMAIL_SUBJECTS

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_verification_email(self, user_id):
    """
    Send email verification email to user.

    Args:
        user_id: UUID of the user to send email to
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        if user.is_email_verified:
            logger.info(f"User {user.email} is already verified, skipping email")
            return

        # Build verification URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        verification_url = f"{frontend_url}/verify-email?token={user.email_verification_token}"

        # Render email template
        context = {
            'user': user,
            'verification_url': verification_url,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/verify_email.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS['verification'],
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Verification email sent to {user.email}")

    except Exception as exc:
        logger.error(f"Failed to send verification email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_password_reset_email(self, user_id):
    """
    Send password reset email to user.

    Args:
        user_id: UUID of the user to send email to
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build reset URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        reset_url = f"{frontend_url}/reset-password?token={user.password_reset_token}"

        # Render email template
        context = {
            'user': user,
            'reset_url': reset_url,
            'expiry_minutes': 15,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/password_reset.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS['password_reset'],
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Password reset email sent to {user.email}")

    except Exception as exc:
        logger.error(f"Failed to send password reset email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_kyc_submitted_email(self, user_id):
    """
    Send KYC submission confirmation email to mentor.

    Args:
        user_id: UUID of the user to send email to
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build status URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        status_url = f"{frontend_url}/kyc/pending"

        # Render email template
        context = {
            'user': user,
            'status_url': status_url,
            'review_days': '2-3',
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/kyc_submitted.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS['kyc_submitted'],
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"KYC submitted email sent to {user.email}")

    except Exception as exc:
        logger.error(f"Failed to send KYC submitted email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_kyc_approved_email(self, user_id):
    """
    Send KYC approval email to mentor.

    Args:
        user_id: UUID of the user to send email to
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build login URL (user needs to log in first to access dashboard)
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        login_url = f"{frontend_url}/login"

        # Render email template
        context = {
            'user': user,
            'dashboard_url': login_url,  # Redirect to login page first
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/kyc_approved.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS['kyc_approved'],
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"KYC approved email sent to {user.email}")

    except Exception as exc:
        logger.error(f"Failed to send KYC approved email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_kyc_rejected_email(self, user_id, rejection_reason):
    """
    Send KYC rejection email to mentor.

    Args:
        user_id: UUID of the user to send email to
        rejection_reason: Reason for rejection
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build KYC URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        kyc_url = f"{frontend_url}/kyc"

        # Render email template
        context = {
            'user': user,
            'kyc_url': kyc_url,
            'rejection_reason': rejection_reason,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/kyc_rejected.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS['kyc_rejected'],
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"KYC rejected email sent to {user.email}")

    except Exception as exc:
        logger.error(f"Failed to send KYC rejected email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_welcome_email(self, user_id):
    """
    Send welcome email after successful email verification.

    Args:
        user_id: UUID of the user to send email to
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build login URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        login_url = f"{frontend_url}/login"

        # Render email template
        context = {
            'user': user,
            'login_url': login_url,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/welcome.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS['welcome'],
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Welcome email sent to {user.email}")

    except Exception as exc:
        logger.error(f"Failed to send welcome email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_eaglet_welcome_email(self, user_id):
    """
    Send welcome email to eaglet after completing onboarding.

    Args:
        user_id: UUID of the user to send email to
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build login URL (user needs to log in first to access dashboard)
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        login_url = f"{frontend_url}/login"
        explore_url = f"{frontend_url}/explore"

        # Render email template
        context = {
            'user': user,
            'dashboard_url': login_url,  # Redirect to login page first
            'explore_url': explore_url,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/eaglet_welcome.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS['eaglet_welcome'],
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Eaglet welcome email sent to {user.email}")

    except Exception as exc:
        logger.error(f"Failed to send eaglet welcome email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_kyc_changes_requested_email(self, user_id, review_notes):
    """
    Send email to mentor when changes are requested on their KYC application.

    Args:
        user_id: UUID of the user to send email to
        review_notes: Notes explaining what changes are needed
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build KYC URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        kyc_url = f"{frontend_url}/kyc"

        # Render email template
        context = {
            'user': user,
            'kyc_url': kyc_url,
            'review_notes': review_notes,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/kyc_changes_requested.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS.get('kyc_changes_requested', 'Action Required: Update Your Mentor Application'),
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"KYC changes requested email sent to {user.email}")

    except Exception as exc:
        logger.error(f"Failed to send KYC changes requested email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


# =============================================================================
# NEW PROFILE TASKS (For both Mentor and Mentee KYC)
# =============================================================================

@shared_task(bind=True, max_retries=3)
def send_profile_submitted_email(self, user_id, role):
    """
    Send profile submission confirmation email to user (mentor or mentee).

    Args:
        user_id: UUID of the user to send email to
        role: 'mentor' or 'mentee'
    """
    try:
        from .models import User
        from django.utils import timezone
        user = User.objects.get(id=user_id)

        # Build status URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')

        # Render email template
        context = {
            'user': user,
            'role': role,
            'frontend_url': frontend_url,
            'submitted_at': timezone.now(),
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/profile_submitted.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS.get('profile_submitted', 'Your Profile is Under Review'),
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Profile submitted email sent to {user.email} ({role})")

    except Exception as exc:
        logger.error(f"Failed to send profile submitted email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_profile_approved_email(self, user_id, role):
    """
    Send profile approval email to user (mentor or mentee).

    Args:
        user_id: UUID of the user to send email to
        role: 'mentor' or 'mentee'
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build dashboard URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        dashboard_url = f"{frontend_url}/dashboard"

        # Choose template based on role
        template = 'emails/mentor_approved.html' if role == 'mentor' else 'emails/mentee_approved.html'
        subject_key = 'mentor_approved' if role == 'mentor' else 'mentee_approved'

        # Render email template
        context = {
            'user': user,
            'dashboard_url': dashboard_url,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string(template, context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS.get(subject_key, f'Congratulations! Your {role.title()} Profile is Approved'),
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Profile approved email sent to {user.email} ({role})")

    except Exception as exc:
        logger.error(f"Failed to send profile approved email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_profile_rejected_email(self, user_id, role, rejection_reason):
    """
    Send profile rejection email to user (mentor or mentee).

    Args:
        user_id: UUID of the user to send email to
        role: 'mentor' or 'mentee'
        rejection_reason: Reason for rejection
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Render email template
        context = {
            'user': user,
            'role': role,
            'rejection_reason': rejection_reason,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/profile_rejected.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS.get('profile_rejected', 'Update Required: Your Profile Application'),
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Profile rejected email sent to {user.email} ({role})")

    except Exception as exc:
        logger.error(f"Failed to send profile rejected email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_profile_changes_requested_email(self, user_id, role, review_notes):
    """
    Send email when changes are requested on a profile (mentor or mentee).

    Args:
        user_id: UUID of the user to send email to
        role: 'mentor' or 'mentee'
        review_notes: Notes explaining what changes are needed
    """
    try:
        from .models import User
        user = User.objects.get(id=user_id)

        # Build profile URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        profile_url = f"{frontend_url}/complete-profile"

        # Render email template
        context = {
            'user': user,
            'role': role,
            'profile_url': profile_url,
            'review_notes': review_notes,
            'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@eaglesneaglets.com'),
        }

        html_message = render_to_string('emails/profile_changes_requested.html', context)
        plain_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=EMAIL_SUBJECTS.get('profile_changes_requested', 'Action Required: Please Update Your Profile'),
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Profile changes requested email sent to {user.email} ({role})")

    except Exception as exc:
        logger.error(f"Failed to send profile changes requested email to user {user_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)

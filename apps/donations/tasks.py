"""
Donation Celery Tasks

Async tasks triggered after successful donations.
All imports are lazy to avoid AppRegistryNotReady errors.
"""

import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_donation_confirmation_email(self, donation_id: str):
    """
    Send a confirmation email to the donor after a successful donation.
    Retries up to 3 times with 60-second delays on failure.
    """
    try:
        from .models import Donation

        donation = (
            Donation.objects.select_related("campaign", "donor")
            .get(id=donation_id)
        )

        if donation.status != Donation.Status.SUCCESS:
            logger.info("Skipping confirmation email — donation %s is not SUCCESS", donation_id)
            return

        # Use Django's email backend (configured in settings)
        from django.core.mail import send_mail
        from django.conf import settings

        recipient_email = (
            donation.donor.email if donation.donor else None
        )
        if not recipient_email:
            logger.info("No email for donation %s — skipping confirmation email", donation_id)
            return

        subject = f"Thank you for your donation to {donation.campaign.title}!"
        message = (
            f"Dear {donation.donor_name},\n\n"
            f"Your donation of {donation.currency} {donation.amount} to "
            f'"{donation.campaign.title}" has been received.\n\n'
            f"Reference: {donation.hubtel_reference}\n\n"
            f"Thank you for your generosity!\n\n"
            f"Eagles & Eaglets Team"
        )

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
            fail_silently=False,
        )

        logger.info("Confirmation email sent for donation %s to %s", donation_id, recipient_email)

    except Exception as exc:
        logger.exception("Failed to send confirmation email for donation %s: %s", donation_id, exc)
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=120)
def send_campaign_milestone_alert(self, campaign_id: str, milestone_pct: int):
    """
    Notify the campaign creator when a milestone (25%, 50%, 75%, 100%) is reached.
    """
    try:
        from .models import Campaign
        from django.core.mail import send_mail
        from django.conf import settings

        campaign = Campaign.objects.select_related("created_by").get(id=campaign_id)
        creator_email = campaign.created_by.email

        subject = f"🎉 {milestone_pct}% milestone reached for '{campaign.title}'!"
        message = (
            f"Great news!\n\n"
            f"Your campaign \"{campaign.title}\" has reached {milestone_pct}% of its goal.\n\n"
            f"Current amount: {campaign.currency} {campaign.current_amount}\n"
            f"Goal: {campaign.currency} {campaign.goal_amount}\n\n"
            f"Keep up the great work!\n\nEagles & Eaglets Team"
        )

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[creator_email],
            fail_silently=False,
        )

        logger.info(
            "Milestone %s%% alert sent for campaign %s to %s",
            milestone_pct,
            campaign_id,
            creator_email,
        )

    except Exception as exc:
        logger.exception("Failed to send milestone alert for campaign %s: %s", campaign_id, exc)
        raise self.retry(exc=exc)

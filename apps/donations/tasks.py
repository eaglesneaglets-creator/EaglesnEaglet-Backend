"""
Donation Celery Tasks

Async tasks triggered after successful donations.
All imports are lazy to avoid AppRegistryNotReady errors.
Emails use the shared themed templates under templates/emails/.
"""

import logging

from celery import shared_task

logger = logging.getLogger(__name__)


def _frontend_url() -> str:
    from django.conf import settings
    return getattr(settings, "FRONTEND_URL", "http://localhost:5173").rstrip("/")


def _support_email() -> str:
    from django.conf import settings
    return (
        getattr(settings, "SUPPORT_EMAIL", None)
        or getattr(settings, "DEFAULT_FROM_EMAIL", "support@eaglesneaglets.com")
    )


def _send_themed(*, subject: str, template: str, context: dict, recipient: str) -> None:
    """Render the themed template and send via Django's mail backend."""
    from django.conf import settings
    from django.core.mail import send_mail
    from django.template.loader import render_to_string
    from django.utils.html import strip_tags

    ctx = {
        "support_email": _support_email(),
        "frontend_url": _frontend_url(),
        **context,
    }
    html_message = render_to_string(template, ctx)
    text_message = strip_tags(html_message)
    send_mail(
        subject=subject,
        message=text_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient],
        html_message=html_message,
        fail_silently=False,
    )


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_donation_confirmation_email(self, donation_id: str):
    """Send a themed confirmation email to the donor after a successful donation."""
    try:
        from .models import Donation

        donation = (
            Donation.objects.select_related("campaign", "donor")
            .get(id=donation_id)
        )

        if donation.status != Donation.Status.SUCCESS:
            logger.info("Skipping confirmation email — donation %s is not SUCCESS", donation_id)
            return

        recipient_email = donation.donor.email if donation.donor else None
        if not recipient_email:
            logger.info("No email for donation %s — skipping confirmation email", donation_id)
            return

        _send_themed(
            subject=f"Thank you for your donation to {donation.campaign.title}",
            template="emails/donation_confirmation.html",
            context={
                "donor_name": donation.donor_name,
                "amount": donation.amount,
                "currency": donation.currency,
                "campaign_title": donation.campaign.title,
                "reference": donation.hubtel_reference,
                "campaign_url": f"{_frontend_url()}/donations/{donation.campaign_id}",
            },
            recipient=recipient_email,
        )

        logger.info("Confirmation email sent for donation %s to %s", donation_id, recipient_email)

    except Exception as exc:
        logger.exception("Failed to send confirmation email for donation %s: %s", donation_id, exc)
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=120)
def send_campaign_milestone_alert(self, campaign_id: str, milestone_pct: int):
    """Notify the campaign creator when a milestone (25/50/75/100%) is reached."""
    try:
        from .models import Campaign

        campaign = Campaign.objects.select_related("created_by").get(id=campaign_id)
        creator_email = campaign.created_by.email

        _send_themed(
            subject=f"🎉 {milestone_pct}% milestone reached for '{campaign.title}'",
            template="emails/campaign_milestone.html",
            context={
                "milestone_pct": milestone_pct,
                "campaign_title": campaign.title,
                "current_amount": campaign.current_amount,
                "goal_amount": campaign.goal_amount,
                "currency": campaign.currency,
                "campaign_url": f"{_frontend_url()}/donations/{campaign.id}",
            },
            recipient=creator_email,
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

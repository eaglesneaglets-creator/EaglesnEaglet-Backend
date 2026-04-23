"""
Donation Services

Business logic for campaign management and Hubtel mobile money donation flow.
"""

import logging
import random
import uuid

from django.conf import settings
from django.core.cache import cache
from django.db import models, transaction
from rest_framework.exceptions import NotFound, ValidationError

from .hubtel import HubtelClient, HubtelSMSClient
from .models import Campaign, Donation, RecurringDonation

logger = logging.getLogger(__name__)


class DonationService:

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    @staticmethod
    def list_active_campaigns():
        return Campaign.objects.filter(is_active=True).select_related("created_by")

    @staticmethod
    def get_campaign(campaign_id: str) -> Campaign:
        try:
            return Campaign.objects.select_related("created_by").get(id=campaign_id)
        except Campaign.DoesNotExist:
            raise NotFound("Campaign not found.")

    @staticmethod
    @transaction.atomic
    def create_campaign(user, data: dict) -> Campaign:
        return Campaign.objects.create(
            created_by=user,
            title=data["title"],
            description=data.get("description", ""),
            goal_amount=data["goal_amount"],
            image_url=data.get("image_url", ""),
            start_date=data.get("start_date"),
            end_date=data.get("end_date"),
        )

    # ------------------------------------------------------------------
    # Donations — initiate
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def initiate_donation(
        campaign_id,
        amount,
        phone_number: str,
        donor_name: str,
        frequency: str,
        is_anonymous: bool,
        message: str,
        donor=None,
        network: str = None,
    ) -> dict:
        """
        Create a pending Donation and call the Hubtel API to send a
        mobile money prompt to the donor's phone.

        Returns a dict with donation_id, reference, and a user-facing message.
        The actual status update happens via the Hubtel callback webhook.
        """
        try:
            campaign = Campaign.objects.get(id=campaign_id, is_active=True)
        except Campaign.DoesNotExist:
            raise NotFound("Campaign not found or is no longer active.")

        phone = HubtelClient.format_phone(phone_number)
        # Use frontend-provided network or auto-detect
        channel = network or HubtelClient.detect_channel(phone)
        reference = f"DON-{uuid.uuid4().hex[:12].upper()}"

        donation = Donation.objects.create(
            campaign=campaign,
            donor=donor,
            amount=amount,
            phone_number=phone,
            donor_name=donor_name,
            hubtel_reference=reference,
            frequency=frequency,
            is_anonymous=is_anonymous,
            message=message,
            status=Donation.Status.PENDING,
        )

        callback_url = f"{settings.BACKEND_URL}/api/v1/donations/callback/payment/"

        try:
            hubtel_response = HubtelClient.initiate_payment(
                reference=reference,
                amount=float(amount),
                phone=phone,
                channel=channel,
                donor_name=donor_name,
                callback_url=callback_url,
            )
            # v1 API returns TransactionId at top level; v2 returns Data.SessionId
            session_id = (
                hubtel_response.get("TransactionId")
                or hubtel_response.get("Data", {}).get("SessionId", "")
            )
            if session_id:
                donation.hubtel_session_id = session_id
                donation.status = Donation.Status.PROCESSING
                donation.save(update_fields=["hubtel_session_id", "status"])
        except ValidationError:
            # Mark as failed if Hubtel rejected the request immediately
            donation.status = Donation.Status.FAILED
            donation.save(update_fields=["status"])
            raise

        logger.info(
            "Donation initiated: reference=%s campaign=%s amount=%s %s",
            reference,
            campaign.title,
            amount,
            campaign.currency,
        )

        return {
            "donation_id": str(donation.id),
            "reference": reference,
            "status": donation.status,
            "message": (
                "A payment prompt has been sent to your phone. "
                "Please approve the payment to complete your donation."
            ),
        }

    # ------------------------------------------------------------------
    # Donations — webhook callback
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def process_callback(callback_data: dict) -> Donation:
        """
        Idempotent handler for Hubtel payment callbacks.

        Hubtel posts to our callback URL after the donor approves or
        rejects the mobile money prompt.

        Idempotency: if the donation is already SUCCESS, return early.
        """
        # v1 API: reference is top-level ClientReference or ClientState
        # v2 API: reference is in Data.ClientReference (kept for safety)
        data = callback_data.get("Data", {})
        reference = (
            callback_data.get("ClientReference")
            or callback_data.get("ClientState")
            or data.get("ClientReference")
        )

        if not reference:
            logger.warning("Hubtel callback received without reference: %s", callback_data)
            raise ValidationError({"callback": "Missing payment reference."})

        try:
            donation = Donation.objects.select_related("campaign").get(hubtel_reference=reference)
        except Donation.DoesNotExist:
            logger.error("Hubtel callback for unknown reference: %s", reference)
            raise NotFound("Donation not found.")

        # Idempotency guard
        if donation.status == Donation.Status.SUCCESS:
            logger.info("Duplicate callback for already-successful donation %s", reference)
            return donation

        # v1 API: success indicated by ResponseCode == "0000" or Status == "Success"
        # v2 API: top-level Status == "Success" (kept for safety)
        status_str = callback_data.get("Status", "")
        response_code = callback_data.get("ResponseCode", "")
        order_info = callback_data.get("OrderInfo", {})
        is_successful = (
            response_code == "0000"
            or status_str.lower() == "success"
            or order_info.get("Payment", {}).get("IsSuccessful", False)
        )

        if is_successful:
            donation.status = Donation.Status.SUCCESS
            # Atomically increment campaign total
            Campaign.objects.filter(id=donation.campaign_id).update(
                current_amount=models.F("current_amount") + donation.amount
            )
            logger.info(
                "Donation SUCCESS: reference=%s amount=%s campaign=%s",
                reference,
                donation.amount,
                donation.campaign.title,
            )
        else:
            donation.status = Donation.Status.FAILED
            logger.info("Donation FAILED: reference=%s", reference)

        donation.save(update_fields=["status"])
        return donation

    # ------------------------------------------------------------------
    # Donations — manual status check (fallback when callback fails)
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def check_and_update_status(donation_id: str) -> dict:
        """
        Check Hubtel for transaction status and update donation if needed.
        Used as fallback when webhook callback fails.

        Returns dict with current status.
        """
        try:
            donation = Donation.objects.select_related("campaign").get(id=donation_id)
        except Donation.DoesNotExist:
            raise NotFound("Donation not found.")

        # If already in terminal state, return current status
        if donation.status in (Donation.Status.SUCCESS, Donation.Status.FAILED):
            return {
                "status": donation.status,
                "donation_id": str(donation.id),
            }

        # Query Hubtel for current status
        hubtel_response = HubtelClient.check_transaction_status(donation.hubtel_reference)
        data = hubtel_response.get("data", {})

        hubtel_status = data.get("status", "").lower()
        logger.info("Hubtel status check for %s: %s", donation.hubtel_reference, hubtel_status)

        # Update status in database
        donation = Donation.objects.select_for_update().get(id=donation_id)

        if hubtel_status == "paid":
            donation.status = Donation.Status.SUCCESS
            Campaign.objects.filter(id=donation.campaign_id).update(
                current_amount=models.F("current_amount") + donation.amount
            )
            logger.info(
                "Donation SUCCESS (status check): reference=%s amount=%s",
                donation.hubtel_reference,
                donation.amount,
            )
        elif hubtel_status in ("unpaid", "failed", "cancelled"):
            donation.status = Donation.Status.FAILED
            logger.info("Donation FAILED (status check): reference=%s", donation.hubtel_reference)
        # Else: still pending, leave as-is

        donation.save(update_fields=["status"])

        return {
            "status": donation.status,
            "donation_id": str(donation.id),
        }

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    @staticmethod
    def get_admin_stats() -> dict:
        """Aggregate stats for the admin analytics dashboard."""
        from django.db.models import Count, Sum
        from django.utils import timezone

        successful = Donation.objects.filter(status=Donation.Status.SUCCESS)
        all_donations = Donation.objects.all()

        # Current calendar month
        now = timezone.now()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        total_raised = successful.aggregate(total=Sum("amount"))["total"] or 0
        monthly_raised = (
            successful.filter(created_at__gte=month_start)
            .aggregate(total=Sum("amount"))["total"] or 0
        )
        total_donations = successful.count()
        active_campaigns = Campaign.objects.filter(is_active=True).count()
        total_attempts = all_donations.count()
        success_rate = (
            round(total_donations / total_attempts * 100, 1) if total_attempts else 0.0
        )
        recent = successful.select_related("campaign", "donor").order_by("-created_at")[:10]

        return {
            "total_raised": total_raised,
            "monthly_raised": monthly_raised,
            "total_donations": total_donations,
            "active_campaigns": active_campaigns,
            "success_rate": success_rate,
            "recent_donations": recent,
        }


class OtpService:
    """
    Phone verification via one-time passcode (OTP) for anonymous donors.

    Flow:
      1. send_otp(phone)    → generates 6-digit code, caches it, sends SMS
      2. verify_otp(phone, code) → validates code, stores a verified token
      3. consume_verified_token(phone) → checks token exists, deletes it (one-use)

    All state lives in Redis (Django cache) — no database writes.
    TTLs:
      - OTP code:          5 minutes  (300 s)
      - Verified token:   10 minutes  (600 s)
      - Rate-limit key:    1 minute   (60 s)  — max 3 sends per minute per phone
    """

    OTP_TTL = 300       # seconds
    TOKEN_TTL = 600     # seconds
    RATE_TTL = 60       # seconds
    MAX_SENDS = 3       # per RATE_TTL window

    @classmethod
    def _otp_key(cls, phone: str) -> str:
        return f"otp:{phone}"

    @classmethod
    def _token_key(cls, phone: str) -> str:
        return f"otp_verified:{phone}"

    @classmethod
    def _rate_key(cls, phone: str) -> str:
        return f"otp_rate:{phone}"

    @classmethod
    def send_otp(cls, phone: str) -> None:
        """
        Generate a 6-digit OTP, store it in cache, and send via Hubtel SMS.
        Raises ValidationError if the rate limit is exceeded or SMS fails.
        """
        # Rate limiting: allow at most MAX_SENDS per RATE_TTL window
        rate_key = cls._rate_key(phone)
        send_count = cache.get(rate_key, 0)
        if send_count >= cls.MAX_SENDS:
            raise ValidationError(
                {"phone": "Too many verification attempts. Please wait a minute and try again."}
            )

        # Generate and store OTP
        otp_code = f"{random.randint(0, 999999):06d}"
        cache.set(cls._otp_key(phone), otp_code, timeout=cls.OTP_TTL)

        # Increment rate counter (set with TTL only on first send)
        if send_count == 0:
            cache.set(rate_key, 1, timeout=cls.RATE_TTL)
        else:
            cache.set(rate_key, send_count + 1, timeout=cls.RATE_TTL)

        # Send SMS — raises ValidationError on failure
        message = (
            f"Your Eagles & Eaglets verification code is: {otp_code}. "
            f"Valid for 5 minutes. Do not share this code."
        )
        HubtelSMSClient.send_sms(to=phone, content=message)
        logger.info("OTP sent to phone ending ...%s", phone[-4:])

    @classmethod
    def verify_otp(cls, phone: str, code: str) -> str:
        """
        Validate the OTP. On success, stores a verified token and returns it.
        The token is a UUID string the frontend must pass with the donation request.
        Raises ValidationError on wrong/expired code.
        """
        stored = cache.get(cls._otp_key(phone))
        if stored is None:
            raise ValidationError(
                {"code": "Verification code has expired. Please request a new one."}
            )
        if stored != code.strip():
            raise ValidationError({"code": "Invalid verification code."})

        # Code is correct — delete it (single-use) and issue a verified token
        cache.delete(cls._otp_key(phone))
        token = uuid.uuid4().hex
        cache.set(cls._token_key(phone), token, timeout=cls.TOKEN_TTL)
        logger.info("OTP verified for phone ending ...%s", phone[-4:])
        return token

    @classmethod
    def consume_verified_token(cls, phone: str, token: str) -> bool:
        """
        Check that `token` matches the stored verified token for `phone`,
        then delete it so it cannot be reused.

        Returns True if valid, raises ValidationError otherwise.
        """
        stored_token = cache.get(cls._token_key(phone))
        if not stored_token or stored_token != token:
            raise ValidationError(
                {"otp_token": "Phone verification required. Please verify your phone number first."}
            )
        cache.delete(cls._token_key(phone))
        return True

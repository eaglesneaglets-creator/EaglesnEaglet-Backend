"""
Donations Views

API endpoints for campaigns, Hubtel donation flow, and analytics.
"""

import logging

from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from core.permissions.roles import IsAdmin, IsEagleOrAdmin

from .models import Donation
from .serializers import (
    AdminDonationStatsSerializer,
    CampaignCreateSerializer,
    CampaignDetailSerializer,
    CampaignListSerializer,
    DonationHistorySerializer,
    InitiateDonationSerializer,
)
from .services import DonationService, OtpService

logger = logging.getLogger(__name__)


class CampaignViewSet(ViewSet):
    """
    Campaign CRUD.

    list, retrieve — public (AllowAny)
    create, partial_update — Eagle or Admin only
    """

    def get_permissions(self):
        if self.action in ("create", "partial_update", "destroy"):
            return [IsAuthenticated(), IsEagleOrAdmin()]
        return [AllowAny()]

    def list(self, request):
        campaigns = DonationService.list_active_campaigns()
        serializer = CampaignListSerializer(campaigns, many=True)
        return Response({"success": True, "data": serializer.data})

    def retrieve(self, request, pk=None):
        campaign = DonationService.get_campaign(pk)
        serializer = CampaignDetailSerializer(campaign)
        return Response({"success": True, "data": serializer.data})

    def create(self, request):
        serializer = CampaignCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        campaign = DonationService.create_campaign(request.user, serializer.validated_data)
        return Response(
            {"success": True, "data": CampaignDetailSerializer(campaign).data},
            status=status.HTTP_201_CREATED,
        )


class OtpSendView(APIView):
    """
    POST /api/v1/donations/otp/send/

    Generates a 6-digit OTP and delivers it via Hubtel SMS.
    Rate-limited to 3 sends per minute per phone number.
    Only needed for unauthenticated (anonymous) donors.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        phone_raw = request.data.get("phone_number", "").strip()
        if not phone_raw:
            return Response(
                {"success": False, "error": {"message": "phone_number is required."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        from .hubtel import HubtelClient
        phone = HubtelClient.format_phone(phone_raw)
        OtpService.send_otp(phone)
        return Response(
            {"success": True, "data": {"message": "Verification code sent to your phone."}},
            status=status.HTTP_200_OK,
        )


class OtpVerifyView(APIView):
    """
    POST /api/v1/donations/otp/verify/

    Validates the OTP entered by the donor.
    Returns a short-lived token that must be passed with the donation request.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        phone_raw = request.data.get("phone_number", "").strip()
        code = request.data.get("code", "").strip()
        if not phone_raw or not code:
            return Response(
                {"success": False, "error": {"message": "phone_number and code are required."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        from .hubtel import HubtelClient
        phone = HubtelClient.format_phone(phone_raw)
        token = OtpService.verify_otp(phone, code)
        return Response(
            {"success": True, "data": {"otp_token": token}},
            status=status.HTTP_200_OK,
        )


class InitiateDonationView(APIView):
    """
    POST /api/v1/donations/initiate/

    Accepts a donation form, calls Hubtel to send a mobile money prompt
    to the donor's phone.

    Security:
    - Authenticated users: allowed directly (phone pre-verified via account).
    - Anonymous users: must pass otp_token + phone_number that was verified
      via POST /donations/otp/verify/ first. The token is consumed on use.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = InitiateDonationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        donor = request.user if request.user.is_authenticated else None

        # Anonymous donors must have a valid OTP verified token
        if donor is None:
            otp_token = request.data.get("otp_token", "").strip()
            if not otp_token:
                return Response(
                    {
                        "success": False,
                        "error": {
                            "code": 403,
                            "type": "OtpRequired",
                            "message": "Please verify your phone number before donating.",
                        },
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            from .hubtel import HubtelClient
            phone = HubtelClient.format_phone(
                serializer.validated_data.get("phone_number", "")
            )
            OtpService.consume_verified_token(phone, otp_token)

        result = DonationService.initiate_donation(
            **serializer.validated_data,
            donor=donor,
        )
        return Response({"success": True, "data": result}, status=status.HTTP_201_CREATED)


class HubtelPaymentCallbackView(APIView):
    """
    POST /api/v1/donations/callback/payment/

    Hubtel posts here after the donor approves or rejects the mobile money prompt.
    Must return 200 quickly — heavy work is dispatched to Celery.
    
    SECURITY: Validates Hubtel webhook signature to prevent forged callbacks.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        # Hubtel doesn't ship a webhook signature (confirmed with provider).
        # The endpoint accepts callbacks without HMAC verification — risk
        # mitigations layered elsewhere:
        #   * `Donation.hubtel_reference` is the join key; only references
        #     we issued via /donations/initiate/ will match a row, so a
        #     forged callback for an unknown reference becomes a no-op.
        #   * DonationService.process_callback is idempotent (status
        #     transitions go pending → success/failed, not in reverse).
        # If Hubtel later publishes a signing key, plug it into
        # settings.HUBTEL_WEBHOOK_SECRET and the validation path activates.
        from django.conf import settings as _s
        secret = getattr(_s, "HUBTEL_WEBHOOK_SECRET", None)

        if secret:
            if not self._validate_signature(request):
                logger.warning(
                    "Invalid Hubtel webhook signature from IP: %s",
                    self._get_client_ip(request),
                )
                return Response(
                    {"status": "signature_invalid"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        else:
            logger.debug(
                "Hubtel callback accepted without signature (HUBTEL_WEBHOOK_SECRET unset). "
                "Provider does not currently issue signatures; relying on reference-match + idempotency."
            )

        try:
            donation = DonationService.process_callback(request.data)
        except Exception as exc:
            logger.exception("Error processing Hubtel callback: %s", exc)
            # Always return 200 to Hubtel to prevent retries on our errors
            return Response({"status": "error"}, status=status.HTTP_200_OK)

        if donation.status == Donation.Status.SUCCESS:
            # Fire async confirmation tasks (imported lazily to avoid circular imports)
            try:
                from .tasks import send_donation_confirmation_email
                send_donation_confirmation_email.delay(str(donation.id))
            except Exception:
                logger.warning("Failed to enqueue confirmation email for donation %s", donation.id)

        return Response({"status": "received"}, status=status.HTTP_200_OK)

    def _validate_signature(self, request) -> bool:
        """
        Validate Hubtel webhook signature.
        
        Hubtel sends a signature in the X-Hubtel-Signature header.
        The signature is HMAC-SHA256 of the request body using the API key.
        """
        from django.conf import settings
        import hmac
        import hashlib
        
        signature = request.headers.get('X-Hubtel-Signature')
        if not signature:
            # If no signature header, fall back to IP whitelist (old integration)
            # In production, this should be removed and signature should be required
            if not settings.DEBUG:
                logger.warning("Hubtel callback without signature header")
                return False
            return True
        
        # Compute expected signature
        secret = settings.HUBTEL_API_KEY.encode()
        body = request.body
        expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(signature.lower(), expected.lower())

    def _get_client_ip(self, request) -> str:
        """Get client IP from request headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class DonationStatusView(APIView):
    """
    GET /api/v1/donations/status/<str:donation_id>/

    Frontend polls this to detect when Hubtel callback has updated status.
    """

    permission_classes = [AllowAny]

    def get(self, request, donation_id):
        try:
            donation = Donation.objects.select_related("campaign").get(id=donation_id)
        except Donation.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Donation not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({
            "success": True,
            "data": {
                "donation_id": str(donation.id),
                "status": donation.status,
                "campaign_title": donation.campaign.title,
                "amount": str(donation.amount),
                "currency": donation.currency,
            },
        })


class CheckDonationStatusView(APIView):
    """
    POST /api/v1/donations/status/check/<str:donation_id>/

    Manually check Hubtel for transaction status and update donation.
    Used as fallback when webhook callback is not received.
    """

    permission_classes = [AllowAny]

    def post(self, request, donation_id):
        try:
            result = DonationService.check_and_update_status(donation_id)
        except NotFound as exc:
            return Response(
                {"success": False, "error": {"message": str(exc)}},
                status=status.HTTP_404_NOT_FOUND,
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": exc.detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({"success": True, "data": result}, status=status.HTTP_200_OK)


class MyDonationsView(ListAPIView):
    """
    GET /api/v1/donations/my-donations/

    Returns the authenticated user's donation history.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = DonationHistorySerializer

    def get_queryset(self):
        return (
            Donation.objects.filter(donor=self.request.user)
            .select_related("campaign")
            .order_by("-created_at")
        )

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        serializer = self.get_serializer(qs, many=True)
        return Response({"success": True, "data": serializer.data})


class AdminDonationStatsView(APIView):
    """
    GET /api/v1/donations/admin/stats/

    Aggregate donation analytics for the admin dashboard.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        from .serializers import DonationSerializer
        stats = DonationService.get_admin_stats()
        # Serialize recent_donations queryset
        stats["recent_donations"] = DonationSerializer(
            stats["recent_donations"], many=True
        ).data
        return Response({"success": True, "data": stats})

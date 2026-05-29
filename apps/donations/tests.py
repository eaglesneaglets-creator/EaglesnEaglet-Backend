"""
Donations App Tests

Tests for HubtelClient, HubtelSMSClient, OtpService, DonationService, and API views.
"""

import uuid
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APIClient

from apps.donations.hubtel import HubtelClient, HubtelSMSClient
from apps.donations.models import Campaign, Donation
from apps.donations.services import OtpService

User = get_user_model()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_cache():
    """Wipe Redis/cache between every test to prevent OTP state leakage."""
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def eagle_user(db):
    """Create test eagle user.
    
    SECURITY NOTE: Password is a clearly labeled test placeholder,
    NOT a real credential.
    """
    return User.objects.create_user(
        email="eagle@test.com",
        password="TestPassword123!",  # Placeholder - not a real credential
        role="eagle",
        first_name="Eagle",
        last_name="Mentor",
        is_email_verified=True,
    )


@pytest.fixture
def eaglet_user(db):
    """Create test eagle user.
    
    SECURITY NOTE: Password is a clearly labeled test placeholder,
    NOT a real credential.
    """
    return User.objects.create_user(
        email="eaglet@test.com",
        password="TestPassword123!",  # Placeholder - not a real credential
        role="eaglet",
        first_name="Eaglet",
        last_name="Mentee",
        is_email_verified=True,
    )


@pytest.fixture
def admin_user(db):
    """Create test admin user.
    
    SECURITY NOTE: Password is a clearly labeled test placeholder,
    NOT a real credential.
    """
    return User.objects.create_user(
        email="admin@test.com",
        password="TestPassword123!",  # Placeholder - not a real credential
        role="admin",
        first_name="Admin",
        last_name="User",
        is_email_verified=True,
    )


@pytest.fixture
def campaign(db, eagle_user):
    return Campaign.objects.create(
        title="Help Eagles Fly",
        description="A great cause",
        goal_amount=Decimal("1000.00"),
        created_by=eagle_user,
    )


@pytest.fixture
def pending_donation(db, campaign, eaglet_user):
    return Donation.objects.create(
        campaign=campaign,
        donor=eaglet_user,
        amount=Decimal("50.00"),
        phone_number="233241234567",
        donor_name="Test Eaglet",
        hubtel_reference=f"DON-{uuid.uuid4().hex[:12].upper()}",
        status=Donation.Status.PENDING,
    )


# ---------------------------------------------------------------------------
# HubtelClient unit tests (v2)
# ---------------------------------------------------------------------------


class TestHubtelClient:

    def test_format_phone_local_to_e164(self):
        assert HubtelClient.format_phone("0241234567") == "233241234567"

    def test_format_phone_already_e164(self):
        assert HubtelClient.format_phone("233241234567") == "233241234567"

    def test_format_phone_plus_prefix(self):
        assert HubtelClient.format_phone("+233241234567") == "233241234567"

    def test_format_phone_strips_spaces(self):
        assert HubtelClient.format_phone("024 123 4567") == "233241234567"

    @patch("apps.donations.hubtel.requests.post")
    def test_initiate_payment_posts_correct_url(self, mock_post):
        """initiate_payment must call the merchant account API."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"ResponseCode": "0000", "Data": {"CheckoutUrl": "https://pay.hubtel.com/abc"}},
        )
        HubtelClient.initiate_payment(
            reference="DON-TEST",
            amount=50.0,
            phone="233241234567",
            donor_name="John",
            callback_url="http://localhost/callback/",
        )
        call_url = mock_post.call_args[0][0]
        assert "rmp.hubtel.com" in call_url
        assert "receive/mobilemoney" in call_url

    @patch("apps.donations.hubtel.requests.post")
    def test_initiate_payment_payload_has_pos_sales_id(self, mock_post):
        """API requires posSalesId field."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"Data": {"CheckoutUrl": "x"}},
        )
        HubtelClient.initiate_payment(
            reference="DON-TEST",
            amount=10.0,
            phone="233241234567",
            donor_name="Jane",
            callback_url="http://localhost/callback/",
        )
        sent_payload = mock_post.call_args[1]["json"]
        assert "posSalesId" in sent_payload

    @patch("apps.donations.hubtel.requests.post")
    def test_initiate_payment_payload_has_client_reference(self, mock_post):
        """clientReference is required for callback matching."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"Data": {}},
        )
        HubtelClient.initiate_payment(
            reference="DON-TEST",
            amount=10.0,
            phone="233241234567",
            donor_name="Jane",
            callback_url="http://localhost/callback/",
        )
        sent_payload = mock_post.call_args[1]["json"]
        assert "clientReference" in sent_payload
        assert sent_payload["clientReference"] == "DON-TEST"


# ---------------------------------------------------------------------------
# HubtelSMSClient unit tests
# ---------------------------------------------------------------------------


class TestHubtelSMSClient:

    @patch("apps.donations.hubtel.requests.post")
    def test_send_sms_posts_to_correct_url(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"status": 0, "messageId": "abc-123"},
        )
        HubtelSMSClient.send_sms(to="233241234567", content="Your code is 123456")
        call_url = mock_post.call_args[0][0]
        assert "sms.hubtel.com/v1/messages/send" in call_url

    @patch("apps.donations.hubtel.requests.post")
    def test_send_sms_uses_correct_payload_fields(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"status": 0, "messageId": "abc-123"},
        )
        HubtelSMSClient.send_sms(to="233241234567", content="Test OTP")
        payload = mock_post.call_args[1]["json"]
        assert payload["From"] == "EaglesNest"
        assert payload["To"] == "233241234567"
        assert payload["Content"] == "Test OTP"

    @patch("apps.donations.hubtel.requests.post")
    def test_send_sms_raises_on_status_nonzero(self, mock_post):
        """Hubtel returns HTTP 201 but status=1 means rejected — must raise."""
        from rest_framework.exceptions import ValidationError
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"status": 1, "statusDescription": "invalid destination"},
        )
        with pytest.raises(ValidationError):
            HubtelSMSClient.send_sms(to="233241234567", content="code")

    @patch("apps.donations.hubtel.requests.post")
    def test_send_sms_passes_credentials_as_query_params_and_basic_auth(self, mock_post):
        """SMS API requires clientid/clientsecret in both query params AND Basic Auth header."""
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"status": 0, "messageId": "abc-123"},
        )
        HubtelSMSClient.send_sms(to="233241234567", content="code")
        call_kwargs = mock_post.call_args[1]
        # Query params must be present
        assert "params" in call_kwargs
        assert "clientid" in call_kwargs["params"]
        assert "clientsecret" in call_kwargs["params"]
        # Basic Auth header must also be present
        headers = call_kwargs.get("headers", {})
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    @patch("apps.donations.hubtel.requests.post")
    def test_send_sms_raises_on_http_400(self, mock_post):
        """HTTP 400 with status=100 = bad credentials — must raise ValidationError."""
        import requests as req
        from rest_framework.exceptions import ValidationError
        mock_response = MagicMock(
            status_code=400,
            text='{"status":100,"statusDescription":"Provided ClientId could not be found"}',
        )
        mock_post.return_value = mock_response
        mock_post.return_value.raise_for_status.side_effect = req.HTTPError(
            response=mock_response
        )
        with pytest.raises(ValidationError):
            HubtelSMSClient.send_sms(to="233241234567", content="code")


# ---------------------------------------------------------------------------
# OtpService unit tests
# ---------------------------------------------------------------------------


class TestOtpService:

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_send_otp_stores_code_in_cache(self, mock_sms):
        """After send_otp, a 6-digit code must exist in cache for that phone."""
        phone = "233241234567"
        OtpService.send_otp(phone)
        stored = cache.get(f"otp:{phone}")
        assert stored is not None
        assert len(stored) == 6
        assert stored.isdigit()

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_send_otp_calls_sms_with_phone(self, mock_sms):
        """SMS must be sent to the formatted phone number."""
        phone = "233241234567"
        OtpService.send_otp(phone)
        mock_sms.assert_called_once()
        assert mock_sms.call_args[1]["to"] == phone or mock_sms.call_args[0][0] == phone

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_send_otp_rate_limits_after_3_sends(self, mock_sms):
        """4th OTP send within 1 minute must be rejected."""
        from rest_framework.exceptions import ValidationError
        phone = "233241234567"
        for _ in range(3):
            OtpService.send_otp(phone)
        with pytest.raises(ValidationError, match="Too many"):
            OtpService.send_otp(phone)

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_verify_otp_returns_token_on_correct_code(self, mock_sms):
        """Correct OTP returns a non-empty token string."""
        phone = "233241234567"
        OtpService.send_otp(phone)
        code = cache.get(f"otp:{phone}")
        token = OtpService.verify_otp(phone, code)
        assert isinstance(token, str)
        assert len(token) == 32  # uuid4().hex

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_verify_otp_deletes_code_after_use(self, mock_sms):
        """OTP code must be deleted from cache after successful verification."""
        phone = "233241234567"
        OtpService.send_otp(phone)
        code = cache.get(f"otp:{phone}")
        OtpService.verify_otp(phone, code)
        assert cache.get(f"otp:{phone}") is None

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_verify_otp_raises_on_wrong_code(self, mock_sms):
        """Wrong OTP must raise ValidationError."""
        from rest_framework.exceptions import ValidationError
        phone = "233241234567"
        OtpService.send_otp(phone)
        with pytest.raises(ValidationError, match="Invalid"):
            OtpService.verify_otp(phone, "000000")

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_verify_otp_raises_on_expired_code(self, mock_sms):
        """No cached OTP (expired or never sent) must raise ValidationError."""
        from rest_framework.exceptions import ValidationError
        with pytest.raises(ValidationError, match="expired"):
            OtpService.verify_otp("233241234567", "123456")

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_consume_verified_token_accepts_valid_token(self, mock_sms):
        """consume_verified_token must return True for the issued token."""
        phone = "233241234567"
        OtpService.send_otp(phone)
        code = cache.get(f"otp:{phone}")
        token = OtpService.verify_otp(phone, code)
        result = OtpService.consume_verified_token(phone, token)
        assert result is True

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_consume_verified_token_is_single_use(self, mock_sms):
        """Token must be deleted after consume — cannot be reused."""
        from rest_framework.exceptions import ValidationError
        phone = "233241234567"
        OtpService.send_otp(phone)
        code = cache.get(f"otp:{phone}")
        token = OtpService.verify_otp(phone, code)
        OtpService.consume_verified_token(phone, token)
        with pytest.raises(ValidationError):
            OtpService.consume_verified_token(phone, token)

    def test_consume_verified_token_raises_on_wrong_token(self):
        """Wrong token for a phone must raise ValidationError."""
        from rest_framework.exceptions import ValidationError
        phone = "233241234567"
        cache.set(f"otp_verified:{phone}", "correct-token", timeout=600)
        with pytest.raises(ValidationError):
            OtpService.consume_verified_token(phone, "wrong-token")


# ---------------------------------------------------------------------------
# OTP API endpoint tests
# ---------------------------------------------------------------------------


class TestOtpSendAPI:

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_send_otp_returns_200(self, mock_sms, api_client):
        mock_sms.return_value = {"status": 0}
        response = api_client.post(
            "/api/v1/donations/otp/send/",
            {"phone_number": "0241234567"},
            format="json",
        )
        assert response.status_code == 200
        assert response.data["success"] is True

    def test_send_otp_missing_phone_returns_400(self, api_client):
        response = api_client.post("/api/v1/donations/otp/send/", {}, format="json")
        assert response.status_code == 400


class TestOtpVerifyAPI:

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_verify_otp_returns_token(self, mock_sms, api_client):
        """Valid OTP must return an otp_token in the response."""
        mock_sms.return_value = {"status": 0}
        phone = "0241234567"
        api_client.post("/api/v1/donations/otp/send/", {"phone_number": phone}, format="json")
        # Grab the code directly from cache (E.164 form)
        code = cache.get("otp:233241234567")
        response = api_client.post(
            "/api/v1/donations/otp/verify/",
            {"phone_number": phone, "code": code},
            format="json",
        )
        assert response.status_code == 200
        assert "otp_token" in response.data["data"]

    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_verify_otp_wrong_code_returns_400(self, mock_sms, api_client):
        mock_sms.return_value = {"status": 0}
        api_client.post("/api/v1/donations/otp/send/", {"phone_number": "0241234567"}, format="json")
        response = api_client.post(
            "/api/v1/donations/otp/verify/",
            {"phone_number": "0241234567", "code": "000000"},
            format="json",
        )
        assert response.status_code == 400

    def test_verify_otp_missing_fields_returns_400(self, api_client):
        response = api_client.post("/api/v1/donations/otp/verify/", {}, format="json")
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Initiate donation tests (OTP-aware)
# ---------------------------------------------------------------------------


class TestInitiateDonation:

    def test_anonymous_without_otp_token_returns_403(self, api_client, campaign):
        """Anonymous donors must be rejected without an OTP token."""
        response = api_client.post(
            "/api/v1/donations/initiate/",
            {
                "campaign_id": str(campaign.id),
                "amount": "20.00",
                "phone_number": "0241234567",
                "donor_name": "John Doe",
                "frequency": "once",
                "is_anonymous": False,
                "message": "",
            },
            format="json",
        )
        assert response.status_code == 403
        assert response.data["error"]["type"] == "OtpRequired"

    @patch("apps.donations.hubtel.HubtelClient.initiate_payment")
    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_anonymous_with_valid_otp_token_succeeds(self, mock_sms, mock_pay, api_client, campaign):
        """Anonymous donor with a valid OTP token must get 201."""
        mock_sms.return_value = {"status": 0}
        mock_pay.return_value = {"Data": {"CheckoutUrl": "https://pay.hubtel.com/abc"}}

        phone = "0241234567"
        # Step 1: send OTP
        api_client.post("/api/v1/donations/otp/send/", {"phone_number": phone}, format="json")
        code = cache.get("otp:233241234567")

        # Step 2: verify OTP → get token
        verify_resp = api_client.post(
            "/api/v1/donations/otp/verify/",
            {"phone_number": phone, "code": code},
            format="json",
        )
        otp_token = verify_resp.data["data"]["otp_token"]

        # Step 3: donate with token
        response = api_client.post(
            "/api/v1/donations/initiate/",
            {
                "campaign_id": str(campaign.id),
                "amount": "20.00",
                "phone_number": phone,
                "donor_name": "John Doe",
                "frequency": "once",
                "is_anonymous": False,
                "message": "",
                "otp_token": otp_token,
            },
            format="json",
        )
        assert response.status_code == 201
        assert "donation_id" in response.data["data"]

    @patch("apps.donations.hubtel.HubtelClient.initiate_payment")
    def test_authenticated_user_skips_otp(self, mock_pay, api_client, campaign, eaglet_user):
        """Authenticated users must be able to donate without any OTP token."""
        mock_pay.return_value = {"Data": {"CheckoutUrl": "https://pay.hubtel.com/abc"}}
        api_client.force_authenticate(user=eaglet_user)
        response = api_client.post(
            "/api/v1/donations/initiate/",
            {
                "campaign_id": str(campaign.id),
                "amount": "50.00",
                "phone_number": "0241234567",
                "donor_name": "Eaglet",
                "frequency": "once",
                "is_anonymous": False,
                "message": "Keep it up!",
            },
            format="json",
        )
        assert response.status_code == 201
        donation_id = response.data["data"]["donation_id"]
        assert Donation.objects.get(id=donation_id).donor == eaglet_user

    @patch("apps.donations.hubtel.HubtelClient.initiate_payment")
    @patch("apps.donations.services.HubtelSMSClient.send_sms")
    def test_otp_token_cannot_be_reused(self, mock_sms, mock_pay, api_client, campaign):
        """A consumed OTP token must be rejected on a second donation attempt."""
        mock_sms.return_value = {"status": 0}
        mock_pay.return_value = {"Data": {"CheckoutUrl": "https://pay.hubtel.com/abc"}}

        phone = "0241234567"
        api_client.post("/api/v1/donations/otp/send/", {"phone_number": phone}, format="json")
        code = cache.get("otp:233241234567")
        verify_resp = api_client.post(
            "/api/v1/donations/otp/verify/",
            {"phone_number": phone, "code": code},
            format="json",
        )
        otp_token = verify_resp.data["data"]["otp_token"]

        donation_payload = {
            "campaign_id": str(campaign.id),
            "amount": "20.00",
            "phone_number": phone,
            "donor_name": "John",
            "frequency": "once",
            "is_anonymous": False,
            "message": "",
            "otp_token": otp_token,
        }
        # First use — should succeed
        api_client.post("/api/v1/donations/initiate/", donation_payload, format="json")
        # Second use — token consumed, must be rejected
        response = api_client.post("/api/v1/donations/initiate/", donation_payload, format="json")
        assert response.status_code in (400, 403)


# ---------------------------------------------------------------------------
# Callback / webhook tests (v2 format)
# ---------------------------------------------------------------------------


class TestHubtelCallback:

    @patch("apps.donations.views.HubtelPaymentCallbackView._validate_signature", return_value=True)
    def test_v2_callback_success_marks_donation(self, mock_sig, api_client, pending_donation, campaign):
        """v2 callback with Status=Success must mark donation as SUCCESS."""
        payload = {
            "Status": "Success",
            "Data": {"ClientReference": pending_donation.hubtel_reference},
        }
        api_client.post("/api/v1/donations/callback/payment/", payload, format="json")
        pending_donation.refresh_from_db()
        assert pending_donation.status == Donation.Status.SUCCESS

    @patch("apps.donations.views.HubtelPaymentCallbackView._validate_signature", return_value=True)
    def test_v2_callback_success_increments_campaign(self, mock_sig, api_client, pending_donation, campaign):
        original_amount = campaign.current_amount
        payload = {
            "Status": "Success",
            "Data": {"ClientReference": pending_donation.hubtel_reference},
        }
        api_client.post("/api/v1/donations/callback/payment/", payload, format="json")
        campaign.refresh_from_db()
        assert campaign.current_amount == original_amount + pending_donation.amount

    @patch("apps.donations.views.HubtelPaymentCallbackView._validate_signature", return_value=True)
    def test_v2_callback_failure_marks_failed(self, mock_sig, api_client, pending_donation):
        payload = {
            "Status": "Failed",
            "Data": {"ClientReference": pending_donation.hubtel_reference},
        }
        api_client.post("/api/v1/donations/callback/payment/", payload, format="json")
        pending_donation.refresh_from_db()
        assert pending_donation.status == Donation.Status.FAILED

    @patch("apps.donations.views.HubtelPaymentCallbackView._validate_signature", return_value=True)
    def test_callback_idempotent(self, mock_sig, api_client, pending_donation, campaign):
        """Duplicate success callbacks must not double-count the amount."""
        payload = {
            "Status": "Success",
            "Data": {"ClientReference": pending_donation.hubtel_reference},
        }
        api_client.post("/api/v1/donations/callback/payment/", payload, format="json")
        api_client.post("/api/v1/donations/callback/payment/", payload, format="json")
        campaign.refresh_from_db()
        assert campaign.current_amount == pending_donation.amount

    @patch("apps.donations.views.HubtelPaymentCallbackView._validate_signature", return_value=True)
    def test_callback_missing_reference_returns_200(self, mock_sig, api_client):
        """Once the signature passes, malformed payloads should still ack
        with 200 so Hubtel doesn't retry on our internal errors."""
        response = api_client.post(
            "/api/v1/donations/callback/payment/",
            {"Status": "Success"},
            format="json",
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Status poll tests
# ---------------------------------------------------------------------------


class TestDonationStatus:

    def test_status_returns_donation_info(self, api_client, pending_donation):
        response = api_client.get(f"/api/v1/donations/status/{pending_donation.id}/")
        assert response.status_code == 200
        assert response.data["data"]["status"] == Donation.Status.PENDING

    @pytest.mark.django_db
    def test_status_unknown_id_returns_404(self, api_client):
        response = api_client.get(f"/api/v1/donations/status/{uuid.uuid4()}/")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Campaign API tests
# ---------------------------------------------------------------------------


class TestCampaignAPI:

    def test_list_campaigns_public(self, api_client, campaign):
        response = api_client.get("/api/v1/donations/campaigns/")
        assert response.status_code == 200
        assert response.data["success"] is True
        assert len(response.data["data"]) == 1

    def test_retrieve_campaign_public(self, api_client, campaign):
        response = api_client.get(f"/api/v1/donations/campaigns/{campaign.id}/")
        assert response.status_code == 200
        assert response.data["data"]["title"] == "Help Eagles Fly"

    def test_create_campaign_requires_eagle(self, api_client, eaglet_user):
        api_client.force_authenticate(user=eaglet_user)
        response = api_client.post(
            "/api/v1/donations/campaigns/",
            {"title": "Test", "goal_amount": "500.00"},
        )
        assert response.status_code == 403

    def test_create_campaign_as_eagle(self, api_client, eagle_user):
        api_client.force_authenticate(user=eagle_user)
        response = api_client.post(
            "/api/v1/donations/campaigns/",
            {"title": "New Campaign", "goal_amount": "500.00"},
        )
        assert response.status_code == 201


# ---------------------------------------------------------------------------
# My Donations tests
# ---------------------------------------------------------------------------


class TestMyDonations:

    def test_my_donations_requires_auth(self, api_client):
        response = api_client.get("/api/v1/donations/my-donations/")
        assert response.status_code == 401

    def test_my_donations_returns_only_own(self, api_client, eaglet_user, pending_donation):
        api_client.force_authenticate(user=eaglet_user)
        response = api_client.get("/api/v1/donations/my-donations/")
        assert response.status_code == 200
        assert len(response.data["data"]) == 1


# ---------------------------------------------------------------------------
# Admin stats tests
# ---------------------------------------------------------------------------


class TestAdminStats:

    def test_admin_stats_requires_admin(self, api_client, eaglet_user):
        api_client.force_authenticate(user=eaglet_user)
        response = api_client.get("/api/v1/donations/admin/stats/")
        assert response.status_code == 403

    def test_admin_stats_as_admin(self, api_client, admin_user):
        api_client.force_authenticate(user=admin_user)
        response = api_client.get("/api/v1/donations/admin/stats/")
        assert response.status_code == 200
        data = response.data["data"]
        assert "total_raised" in data
        assert "total_donations" in data
        assert "success_rate" in data

"""
Hubtel API Clients

HubtelClient  — Direct Receive Money v2 (mobile money payments)
HubtelSMSClient — Simple SMS v1 (OTP delivery for anonymous donors)

Security note:
- API credentials transmitted via HTTP Basic Auth (Base64-encoded, HTTPS only)
- No card data ever handled — mobile money prompt goes directly to user's phone
"""

import base64
import logging
import re

import requests
from django.conf import settings
from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)


class HubtelClient:
    """
    Thin wrapper around the Hubtel Receive Money API.
    All amounts are in Ghana Cedis (GHS) as float/Decimal.
    """

    BASE_URL = "https://rmp.hubtel.com/merchantaccount/merchants/{account}/receive/mobilemoney"
    STATUS_URL = "https://rmp.hubtel.com/merchantaccount/merchants/{account}/transactions/status"

    # Ghana network channel detection
    _MTN_PREFIXES = ("024", "054", "055", "059", "025", "026")
    _VODAFONE_PREFIXES = ("020", "050")
    _AIRTELTIGO_PREFIXES = ("027", "057", "026", "056")

    @staticmethod
    def _auth_header() -> dict:
        """Basic auth header from HUBTEL_API_KEY:HUBTEL_API_SECRET."""
        api_key = settings.HUBTEL_API_KEY
        api_secret = settings.HUBTEL_API_SECRET
        credentials = base64.b64encode(
            f"{api_key}:{api_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {credentials}", "Content-Type": "application/json"}

    @classmethod
    def detect_channel(cls, phone: str) -> str:
        """
        Detect Ghana mobile network from phone number prefix.
        Returns Hubtel channel string: mtn-gh, vodafone-gh, or tigo-gh.
        """
        digits = re.sub(r"[\s\-\(\)+]", "", phone)
        # Normalise to local format for prefix matching
        local = digits[3:] if digits.startswith("233") else digits
        local = "0" + local if not local.startswith("0") else local

        if local.startswith(cls._MTN_PREFIXES):
            return "mtn-gh"
        if local.startswith(cls._VODAFONE_PREFIXES):
            return "vodafone-gh"
        return "tigo-gh"

    @staticmethod
    def format_phone(phone: str) -> str:
        """
        Normalise a Ghana phone number to E.164 (233XXXXXXXXX).

        Accepts:
          - 024XXXXXXX   → 233244XXXXXX
          - +233XXXXXXXX → 233XXXXXXXX
          - 233XXXXXXXXX → unchanged
        """
        digits = re.sub(r"[\s\-\(\)]", "", phone)
        if digits.startswith("+"):
            digits = digits[1:]
        if digits.startswith("0"):
            digits = "233" + digits[1:]
        return digits

    @staticmethod
    def to_local_format(phone: str) -> str:
        """
        Convert E.164 (233XXXXXXXXX) back to local 10-digit format (0XXXXXXXXX).
        Hubtel v1 API requires local format for CustomerMsisdn.
        """
        digits = re.sub(r"[\s\-\(\)+]", "", phone)
        if digits.startswith("233"):
            digits = "0" + digits[3:]
        return digits

    @classmethod
    def initiate_payment(
        cls,
        reference: str,
        amount: float,
        phone: str,
        donor_name: str,
        callback_url: str,
        channel: str = None,
    ) -> dict:
        """
        Send a Receive Money request to Hubtel API.

        Hubtel dispatches a USSD/prompt to the user's phone.
        Returns the raw Hubtel response dict.
        Raises ValidationError on API or network errors.
        """
        account = settings.HUBTEL_POS_SALES_ID or settings.HUBTEL_MERCHANT_ID or ''
        url = cls.BASE_URL.format(account=account)

        # Use provided channel or auto-detect from phone number
        detected_channel = channel or cls.detect_channel(phone)

        payload = {
            "customerName": donor_name,
            "customerMsisdn": cls.format_phone(phone),
            "channel": detected_channel,
            "amount": float(amount),
            "primaryCallbackUrl": callback_url,
            "clientReference": reference,
            "description": "Donation via Eagles & Eaglets",
        }

        logger.info("Hubtel initiating payment to URL: %s with channel: %s", url, detected_channel)

        try:
            resp = requests.post(
                url,
                json=payload,
                headers=cls._auth_header(),
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as exc:
            logger.error(
                "Hubtel payment initiation failed for reference %s: status=%s response=%s",
                reference,
                exc.response.status_code,
                exc.response.text[:500],
            )
            raise ValidationError(
                {"payment": "Payment provider rejected the request. Please check your phone number and try again."}
            )
        except requests.RequestException as exc:
            logger.error("Hubtel network error for reference %s: %s", reference, exc)
            raise ValidationError(
                {"payment": "Unable to reach the payment provider. Please try again."}
            )

    @classmethod
    def check_transaction_status(cls, client_reference: str) -> dict:
        """
        Query Hubtel for the current status of a transaction.

        Returns the raw Hubtel response dict.
        """
        account = settings.HUBTEL_POS_SALES_ID
        url = f"{cls.STATUS_URL.format(account=account)}/{client_reference}"
        try:
            resp = requests.get(url, headers=cls._auth_header(), timeout=15)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as exc:
            logger.error(
                "Hubtel status check failed for %s: status=%s response=%s",
                client_reference,
                exc.response.status_code,
                exc.response.text[:300],
            )
            raise ValidationError({"payment": "Could not retrieve transaction status."})
        except requests.RequestException as exc:
            logger.error("Hubtel status check network error for %s: %s", client_reference, exc)
            raise ValidationError({"payment": "Unable to reach the payment provider."})


class HubtelSMSClient:
    """
    Thin wrapper around the Hubtel Simple SMS v1 API.
    Used exclusively for OTP delivery to anonymous donors.

    POST https://sms.hubtel.com/v1/messages/send?clientid=X&clientsecret=X
    Auth: query parameters (NOT Basic Auth — separate Programmable Keys credentials)
    Success: HTTP 201 + body.status == 0
    """

    SMS_URL = "https://sms.hubtel.com/v1/messages/send"

    @classmethod
    def send_sms(cls, to: str, content: str) -> dict:
        """
        Send an SMS to a single Ghana number (E.164 format: 233XXXXXXXXX).

        Returns the Hubtel response dict on success.
        Raises ValidationError on API errors, auth failures, or network issues.
        """
        payload = {
            "From": settings.HUBTEL_SMS_SENDER_ID,
            "To": to,
            "Content": content,
        }

        credentials = base64.b64encode(
            f"{settings.HUBTEL_SMS_CLIENT_ID}:{settings.HUBTEL_SMS_CLIENT_SECRET}".encode()
        ).decode()

        try:
            resp = requests.post(
                cls.SMS_URL,
                json=payload,
                params={
                    "clientid": settings.HUBTEL_SMS_CLIENT_ID,
                    "clientsecret": settings.HUBTEL_SMS_CLIENT_SECRET,
                },
                headers={
                    "Authorization": f"Basic {credentials}",
                    "Content-Type": "application/json",
                },
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            # Hubtel returns HTTP 201 for queued messages, but status 0 = success
            if data.get("status") != 0:
                logger.error(
                    "Hubtel SMS rejected: status=%s desc=%s to=%s",
                    data.get("status"),
                    data.get("statusDescription"),
                    to,
                )
                raise ValidationError({"sms": "Failed to send verification code. Please try again."})
            logger.info("Hubtel SMS sent: messageId=%s to=%s", data.get("messageId"), to)
            return data
        except requests.HTTPError as exc:
            status_code = exc.response.status_code
            if status_code == 401:
                logger.error("Hubtel SMS auth failure (check API credentials)")
                raise ValidationError({"sms": "SMS service authentication failed."})
            if status_code == 402:
                logger.error("Hubtel SMS insufficient credit")
                raise ValidationError({"sms": "SMS service temporarily unavailable."})
            logger.error(
                "Hubtel SMS HTTP error: status=%s response=%s",
                status_code,
                exc.response.text[:300],
            )
            raise ValidationError({"sms": "Failed to send verification code. Please try again."})
        except requests.RequestException as exc:
            logger.error("Hubtel SMS network error: %s", exc)
            raise ValidationError({"sms": "Unable to reach SMS service. Please try again."})

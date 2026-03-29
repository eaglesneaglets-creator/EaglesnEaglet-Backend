"""
Paystack Payment Service

Handles payment initialization, verification, and webhook signature validation.

Security notes:
- validate_webhook_signature uses hmac.compare_digest (constant-time) to prevent timing attacks
- The secret key is never logged
- No card data (PAN, CVV) is stored or logged — Paystack handles tokenization
"""

import hashlib
import hmac
import logging

import paystack
from django.conf import settings
from rest_framework.exceptions import ValidationError

from paystack.api.transaction_ import Transaction

logger = logging.getLogger(__name__)


class PaystackService:

    @staticmethod
    def _configure():
        """Set the Paystack SDK secret key from Django settings."""
        paystack.api_key = settings.PAYSTACK_SECRET_KEY

    @staticmethod
    def initialize_payment(order, user) -> dict:
        """
        Initialize a Paystack transaction for the given order.

        Returns:
            { "authorization_url": str, "reference": str }

        The reference is the Order UUID — serves as the idempotency key.
        Amount is always in pesewas (GHS minor unit) = total_amount * 100.
        """
        PaystackService._configure()

        email = user.email if user else order.guest_email
        if not email:
            raise ValidationError({"payment": "No email address available for payment."})

        # Amount MUST be an integer in the currency's minor unit (pesewas for GHS)
        amount_minor = int(order.total_amount * 100)
        reference = str(order.id)
        callback_url = f"{settings.FRONTEND_URL}/store/orders/{order.id}?verify=1"

        try:
            response = Transaction.initialize(
                email=email,
                amount=amount_minor,
                reference=reference,
                callback_url=callback_url,
                currency="GHS",
            )
        except Exception as exc:
            logger.error("Paystack initialize_payment failed for order %s: %s", order.id, exc)
            raise ValidationError({"payment": "Payment initialization failed. Please try again."})

        data = response.data if hasattr(response, "data") else {}
        if not data:
            raise ValidationError({"payment": "Unexpected response from payment provider."})

        authorization_url = (
            data.get("authorization_url")
            if isinstance(data, dict)
            else getattr(data, "authorization_url", None)
        )

        if not authorization_url:
            raise ValidationError({"payment": "No authorization URL returned from payment provider."})

        logger.info("Payment initialized for order %s", order.id)
        return {
            "authorization_url": authorization_url,
            "reference": reference,
        }

    @staticmethod
    def verify_payment(reference: str) -> dict:
        """
        Verify a Paystack transaction by reference.

        Returns a dict with at minimum:
            { "status": "success" | "failed" | "abandoned", "id": <transaction_id> }

        Raises ValidationError if the reference is not found.
        """
        PaystackService._configure()

        try:
            response = Transaction.verify(reference=reference)
        except Exception as exc:
            logger.error("Paystack verify_payment failed for reference %s: %s", reference, exc)
            raise ValidationError({"payment": "Payment verification failed. Please try again."})

        data = response.data if hasattr(response, "data") else {}
        if not data:
            raise ValidationError({"payment": "Unexpected response from payment provider."})

        # Normalise: SDK may return an object or a dict
        if isinstance(data, dict):
            return data
        # Object with attributes — convert to dict for consistent downstream use
        return {
            "status": getattr(data, "status", None),
            "id": getattr(data, "id", None),
            "reference": getattr(data, "reference", reference),
            "amount": getattr(data, "amount", None),
            "gateway_response": getattr(data, "gateway_response", None),
        }

    @staticmethod
    def validate_webhook_signature(payload: bytes, signature: str) -> bool:
        """
        Validate a Paystack webhook HMAC-SHA512 signature.

        Uses hmac.compare_digest for constant-time comparison — this prevents
        timing-based attacks that could allow an attacker to infer the secret key
        byte-by-byte by measuring response latency differences.

        Args:
            payload: Raw request body bytes (before any JSON parsing)
            signature: Value of the X-Paystack-Signature header

        Returns:
            True if signature is valid, False otherwise.
            NEVER raises — invalid signatures always return False.
        """
        if not signature or not payload:
            return False

        secret = settings.PAYSTACK_SECRET_KEY
        if not secret:
            logger.warning("PAYSTACK_SECRET_KEY is not configured — webhook validation will always fail.")
            return False

        try:
            computed = hmac.new(
                secret.encode("utf-8"),
                payload,
                hashlib.sha512,
            ).hexdigest()
            # constant-time comparison — NEVER use == here
            return hmac.compare_digest(computed, signature)
        except Exception:
            return False
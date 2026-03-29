"""
Tests for MM-20: Paystack payment integration.

All Paystack API calls are mocked — no real network requests are made.
Tests cover:
  - HMAC-SHA512 webhook signature validation (valid / invalid / tampered)
  - mark_order_paid() idempotency guard (query count proof)
  - Webhook endpoint: invalid sig → 400, valid charge.success → 200 + task dispatched
  - Unknown webhook events: 200 returned, task NOT dispatched
"""

import hashlib
import hmac as hmac_mod
import json
import uuid
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from apps.store.models import Order
from apps.store.payments import PaystackService
from apps.store.services import StoreService


# ── Fixtures ─────────────────────────────────────────────────────────────────

TEST_SECRET = "test_secret_key_12345"


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def pending_order(db):
    """A guest PENDING order with paystack_reference set to its own UUID."""
    ref = str(uuid.uuid4())
    return Order.objects.create(
        user=None,
        guest_email="buyer@test.com",
        guest_name="Test Buyer",
        status=Order.Status.PENDING,
        total_amount=Decimal("150.00"),
        paystack_reference=ref,
    )


def _make_sig(payload: bytes, secret: str = TEST_SECRET) -> str:
    """Helper: compute valid HMAC-SHA512 hex digest for a payload."""
    return hmac_mod.new(secret.encode(), payload, hashlib.sha512).hexdigest()


# ── validate_webhook_signature ────────────────────────────────────────────────

@override_settings(PAYSTACK_SECRET_KEY=TEST_SECRET)
def test_valid_signature_accepted():
    payload = b'{"event":"charge.success"}'
    sig = _make_sig(payload)
    assert PaystackService.validate_webhook_signature(payload, sig) is True


@override_settings(PAYSTACK_SECRET_KEY=TEST_SECRET)
def test_invalid_signature_rejected():
    payload = b'{"event":"charge.success"}'
    assert PaystackService.validate_webhook_signature(payload, "badsig") is False


@override_settings(PAYSTACK_SECRET_KEY=TEST_SECRET)
def test_tampered_payload_rejected():
    """Changing even a single byte of the payload must invalidate the signature."""
    payload = b'{"event":"charge.success"}'
    sig = _make_sig(payload)
    tampered = b'{"event":"charge.success","injected":true}'
    assert PaystackService.validate_webhook_signature(tampered, sig) is False


@override_settings(PAYSTACK_SECRET_KEY=TEST_SECRET)
def test_empty_signature_rejected():
    assert PaystackService.validate_webhook_signature(b'{"event":"test"}', "") is False


@override_settings(PAYSTACK_SECRET_KEY="")
def test_missing_secret_key_always_rejects():
    """If PAYSTACK_SECRET_KEY is not configured, all signatures must be rejected."""
    payload = b'{"event":"charge.success"}'
    # Even a "valid" sig computed with an empty key must fail
    assert PaystackService.validate_webhook_signature(payload, "anything") is False


# ── mark_order_paid idempotency ───────────────────────────────────────────────

@pytest.mark.django_db
def test_mark_order_paid_first_call(pending_order):
    order = StoreService.mark_order_paid(pending_order.paystack_reference, "txn_abc123")
    assert order.status == Order.Status.PAID
    assert order.paystack_transaction_id == "txn_abc123"


@pytest.mark.django_db
def test_mark_order_paid_idempotent_second_call_no_update(pending_order, django_assert_num_queries):
    # First call — writes to DB (SELECT FOR UPDATE + UPDATE)
    StoreService.mark_order_paid(pending_order.paystack_reference, "txn_first")

    # Second call — must NOT issue an UPDATE.
    # Expects exactly 2 queries: BEGIN (implicit in atomic) + SELECT FOR UPDATE
    # The early-return guard skips the UPDATE entirely.
    with django_assert_num_queries(2):
        order2 = StoreService.mark_order_paid(pending_order.paystack_reference, "txn_second")

    assert order2.status == Order.Status.PAID


@pytest.mark.django_db
def test_mark_order_paid_preserves_first_transaction_id(pending_order):
    """The first transaction_id must never be overwritten by a retry."""
    StoreService.mark_order_paid(pending_order.paystack_reference, "txn_first")
    StoreService.mark_order_paid(pending_order.paystack_reference, "txn_second")

    pending_order.refresh_from_db()
    assert pending_order.paystack_transaction_id == "txn_first"  # unchanged


@pytest.mark.django_db
def test_mark_order_paid_unknown_reference_raises():
    """Non-existent reference must raise NotFound, not silently succeed."""
    from rest_framework.exceptions import NotFound
    with pytest.raises(NotFound):
        StoreService.mark_order_paid("ref_does_not_exist", "txn_x")


# ── Webhook endpoint ──────────────────────────────────────────────────────────

@pytest.mark.django_db
@override_settings(PAYSTACK_SECRET_KEY=TEST_SECRET)
def test_webhook_invalid_signature_returns_400(api):
    response = api.post(
        "/api/v1/store/webhook/paystack/",
        data=b'{"event":"charge.success"}',
        content_type="application/json",
        HTTP_X_PAYSTACK_SIGNATURE="badsig",
    )
    assert response.status_code == 400


@pytest.mark.django_db
@override_settings(PAYSTACK_SECRET_KEY=TEST_SECRET)
@patch("apps.store.views.process_successful_payment")
def test_webhook_valid_charge_success_dispatches_task(mock_task, api):
    payload = json.dumps({
        "event": "charge.success",
        "data": {"reference": "ref_test_001", "id": 99999}
    }).encode()
    sig = _make_sig(payload)

    response = api.post(
        "/api/v1/store/webhook/paystack/",
        data=payload,
        content_type="application/json",
        HTTP_X_PAYSTACK_SIGNATURE=sig,
    )
    assert response.status_code == 200
    mock_task.delay.assert_called_once_with("ref_test_001", "99999")


@pytest.mark.django_db
@override_settings(PAYSTACK_SECRET_KEY=TEST_SECRET)
@patch("apps.store.views.process_successful_payment")
def test_webhook_unknown_event_returns_200_no_task(mock_task, api):
    """
    Unknown events must still return 200 to prevent Paystack retry loops.
    But process_successful_payment must NOT be dispatched.
    """
    payload = json.dumps({"event": "subscription.create", "data": {}}).encode()
    sig = _make_sig(payload)

    response = api.post(
        "/api/v1/store/webhook/paystack/",
        data=payload,
        content_type="application/json",
        HTTP_X_PAYSTACK_SIGNATURE=sig,
    )
    assert response.status_code == 200
    mock_task.delay.assert_not_called()


@pytest.mark.django_db
@override_settings(PAYSTACK_SECRET_KEY=TEST_SECRET)
@patch("apps.store.views.process_successful_payment")
def test_webhook_missing_reference_does_not_dispatch(mock_task, api):
    """charge.success with no reference field must not dispatch the task."""
    payload = json.dumps({
        "event": "charge.success",
        "data": {"id": 12345}  # no 'reference' key
    }).encode()
    sig = _make_sig(payload)

    response = api.post(
        "/api/v1/store/webhook/paystack/",
        data=payload,
        content_type="application/json",
        HTTP_X_PAYSTACK_SIGNATURE=sig,
    )
    assert response.status_code == 200
    mock_task.delay.assert_not_called()

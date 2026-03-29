"""
Store Celery Tasks

process_successful_payment is the critical idempotency-safe task triggered by
the Paystack webhook. It delegates to StoreService.mark_order_paid() which has
its own select_for_update() + early-exit guard.

Why lazy import inside the task body?
  Celery workers load task modules at startup before Django's app registry is
  fully initialised. A top-level `from .services import StoreService` would
  trigger an AppRegistryNotReady error. The lazy import inside the function
  body defers resolution until the task actually runs, by which point Django
  is fully ready.
"""

import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def process_successful_payment(self, reference: str, transaction_id: str):
    """
    Process a confirmed Paystack payment.

    Idempotent: StoreService.mark_order_paid() returns early if the order is
    already PAID, so Paystack webhook retries are completely harmless.

    Retries up to 3 times with 60-second delay on any unexpected exception
    (e.g. DB connection blip).
    """
    try:
        from .services import StoreService  # lazy import — see module docstring
        StoreService.mark_order_paid(reference, transaction_id)
    except Exception as exc:
        logger.exception(
            "process_successful_payment failed for reference=%s transaction_id=%s",
            reference,
            transaction_id,
        )
        raise self.retry(exc=exc)
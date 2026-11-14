"""Fernet key helpers with no Django model/settings dependencies.

This module is imported by ``settings/production.py`` at settings-load time, so
it MUST NOT import ``django.conf.settings``, ``django.db`` or anything that
touches the app registry. Keep it to ``cryptography`` and
``django.core.exceptions`` (which is settings-free).
"""
from __future__ import annotations

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured


def build_cipher(key: str | bytes | None) -> Fernet | None:
    """Return a Fernet cipher for ``key``, or None if it is empty or malformed."""
    if not key or not str(key).strip():
        return None
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError):
        return None


def require_encryption_key(key: str | bytes | None) -> str | bytes:
    """Return ``key`` if it is a usable Fernet key; raise otherwise.

    For production settings to call at import time, so a deployment WITHOUT field
    encryption refuses to boot instead of quietly writing national IDs in
    plaintext — which is exactly what happened: ``EncryptedCharField`` treats a
    missing key as "passthrough" (right for local dev) and only logs a warning.

    A malformed key is rejected too. Otherwise a typo'd value would fall back to
    plaintext all the same.

    The key itself is never included in the error message.
    """
    if not key or not str(key).strip():
        raise ImproperlyConfigured(
            "ENCRYPTION_KEY is not set. Production must encrypt KYC national IDs at "
            "rest. Generate one with: python -c \"from cryptography.fernet import "
            "Fernet; print(Fernet.generate_key().decode())\" — then store it safely: "
            "if this key is ever lost or changed, already-encrypted data is unrecoverable. "
            "Every process that loads production settings (web, celery worker, "
            "celery beat, one-off manage.py commands) needs this variable."
        )
    if build_cipher(key) is None:
        raise ImproperlyConfigured(
            "ENCRYPTION_KEY is set but is not a valid Fernet key (expected 32 "
            "url-safe base64-encoded bytes, 44 characters)."
        )
    return key

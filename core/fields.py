"""Custom model fields.

EncryptedCharField — transparent Fernet encryption-at-rest for sensitive PII
(e.g. KYC national ID numbers). See the class docstring for behavior.
"""
import logging

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)

_MISSING_KEY_WARNED = False


def _get_cipher():
    """Return a Fernet cipher from settings.ENCRYPTION_KEY, or None if unset/invalid.

    None means "passthrough" — store/read plaintext. This keeps local dev (no key)
    working while production (key set) encrypts at rest.
    """
    global _MISSING_KEY_WARNED
    key = getattr(settings, 'ENCRYPTION_KEY', '') or ''
    if not key:
        if not _MISSING_KEY_WARNED:
            logger.warning(
                'ENCRYPTION_KEY not set — PII fields stored as plaintext. '
                'Set ENCRYPTION_KEY in production.'
            )
            _MISSING_KEY_WARNED = True
        return None
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError):
        logger.error('ENCRYPTION_KEY is set but invalid — field encryption disabled.')
        return None


def require_encryption_key(key):
    """Return ``key`` if it is a usable Fernet key; raise otherwise.

    For production settings to call at import time, so a deployment WITHOUT field
    encryption refuses to boot instead of quietly writing national IDs in
    plaintext — which is exactly what happened: ``_get_cipher`` treats a missing
    key as "passthrough" (right for local dev) and only logs a warning.

    A malformed key is rejected too. Otherwise a typo'd value would reach
    ``_get_cipher``, log an error, and fall back to plaintext all the same.

    The key itself is never included in the error message.
    """
    from django.core.exceptions import ImproperlyConfigured

    if not key or not str(key).strip():
        raise ImproperlyConfigured(
            "ENCRYPTION_KEY is not set. Production must encrypt KYC national IDs at "
            "rest. Generate one with: python -c \"from cryptography.fernet import "
            "Fernet; print(Fernet.generate_key().decode())\" — then store it safely: "
            "if this key is ever lost or changed, already-encrypted data is unrecoverable."
        )
    try:
        Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(
            "ENCRYPTION_KEY is set but is not a valid Fernet key (expected 32 "
            "url-safe base64-encoded bytes, 44 characters)."
        ) from exc
    return key


class EncryptedCharField(models.TextField):
    """TextField that encrypts its value at rest with Fernet (symmetric AES).

    - Key set: encrypt on write, decrypt on read.
    - Key unset (local dev): passthrough plaintext.
    - Legacy-tolerant: a stored value that is not a valid Fernet token is returned
      as-is on read, so pre-encryption rows still work until re-saved/migrated.

    Stored as TEXT because Fernet ciphertext is much longer than the plaintext.
    Note: encrypted values are NOT queryable by value (random IV per encrypt) and
    cannot be uniquely indexed — only use this for store/display PII, never lookups.
    """

    description = 'Fernet-encrypted text stored at rest'

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value in (None, ''):
            return value
        cipher = _get_cipher()
        if cipher is None:
            return value
        return cipher.encrypt(str(value).encode()).decode()

    def from_db_value(self, value, _expression, _connection):
        if value in (None, ''):
            return value
        cipher = _get_cipher()
        if cipher is None:
            return value
        try:
            return cipher.decrypt(value.encode()).decode()
        except (InvalidToken, ValueError):
            # Legacy plaintext (pre-encryption) — return unchanged.
            return value

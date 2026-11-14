"""Custom model fields.

EncryptedCharField — transparent Fernet encryption-at-rest for sensitive PII
(e.g. KYC national ID numbers). See the class docstring for behavior.
"""
import logging

from cryptography.fernet import InvalidToken
from django.conf import settings
from django.db import models

# Key validation lives in the dependency-free core.crypto so production settings
# can import it at load time. Re-exported here for backwards compatibility.
from core.crypto import build_cipher, require_encryption_key  # noqa: F401

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
    cipher = build_cipher(key)
    if cipher is None:
        logger.error('ENCRYPTION_KEY is set but invalid — field encryption disabled.')
    return cipher


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

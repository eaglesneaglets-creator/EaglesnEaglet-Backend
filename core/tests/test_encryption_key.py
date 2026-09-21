"""ENCRYPTION_KEY handling: the production startup guard and the backfill command.

Background: production ran with no ENCRYPTION_KEY. EncryptedCharField treats a
missing key as "passthrough", so KYC national IDs were written in PLAINTEXT and
the only signal was a log warning. Two gaps closed here:

1. Nothing stopped production booting without a key  → `require_encryption_key`.
2. Migration 0019's backfill was a no-op while the key was unset and never
   re-runs, so existing rows stay plaintext after the key is added
   → `manage.py reencrypt_national_ids`.
"""
import pytest
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db.models import TextField
from django.db.models.functions import Cast

from apps.users.models import MenteeKYC, MentorKYC, User
from core.fields import require_encryption_key

NATIONAL_ID = "GHA-123456789-0"


# ── Startup guard ──────────────────────────────────────────────────────────

def test_guard_accepts_a_valid_fernet_key():
    key = Fernet.generate_key().decode()
    assert require_encryption_key(key) == key


@pytest.mark.parametrize("missing", ["", None, "   "])
def test_guard_rejects_a_missing_key(missing):
    with pytest.raises(ImproperlyConfigured, match="ENCRYPTION_KEY is not set"):
        require_encryption_key(missing)


@pytest.mark.parametrize("bad", ["not-a-key", "abc123", "x" * 44])
def test_guard_rejects_a_malformed_key(bad):
    # A typo'd key must fail at boot — otherwise _get_cipher() logs an error and
    # silently falls back to plaintext, the exact failure this guard exists for.
    with pytest.raises(ImproperlyConfigured, match="not a valid Fernet key"):
        require_encryption_key(bad)


def test_guard_never_echoes_the_key_in_its_error():
    bad = "super-secret-but-malformed-value"
    with pytest.raises(ImproperlyConfigured) as exc:
        require_encryption_key(bad)
    assert bad not in str(exc.value)


# ── Backfill command ───────────────────────────────────────────────────────

def _raw(model, pk):
    """The value as stored in the database, bypassing the field's decryption."""
    return (
        model.objects.filter(pk=pk)
        .annotate(raw=Cast("national_id_number", TextField()))
        .values_list("raw", flat=True)
        .get()
    )


def _user(email, role):
    return User.objects.create_user(email=email, password="x", first_name="K", last_name="Y", role=role)


@pytest.fixture
def plaintext_rows(db, settings):
    """KYC rows written while NO key was configured — i.e. production's state."""
    settings.ENCRYPTION_KEY = ""
    mentee = MenteeKYC.objects.create(user=_user("bf-mentee@test.local", "eaglet"), national_id_number=NATIONAL_ID)
    mentor = MentorKYC.objects.create(user=_user("bf-mentor@test.local", "eagle"), national_id_number=NATIONAL_ID)
    assert _raw(MenteeKYC, mentee.pk) == NATIONAL_ID  # precondition: really plaintext
    return mentee, mentor


@pytest.mark.django_db
def test_backfill_encrypts_existing_plaintext_rows(plaintext_rows, settings):
    mentee, mentor = plaintext_rows
    settings.ENCRYPTION_KEY = Fernet.generate_key().decode()

    call_command("reencrypt_national_ids")

    for model, row in ((MenteeKYC, mentee), (MentorKYC, mentor)):
        stored = _raw(model, row.pk)
        assert stored != NATIONAL_ID, "still plaintext at rest"
        assert NATIONAL_ID not in stored
        # ...and the application still reads back the original value.
        assert model.objects.get(pk=row.pk).national_id_number == NATIONAL_ID


@pytest.mark.django_db
def test_backfill_is_idempotent(plaintext_rows, settings):
    mentee, _ = plaintext_rows
    settings.ENCRYPTION_KEY = Fernet.generate_key().decode()

    call_command("reencrypt_national_ids")
    first = _raw(MenteeKYC, mentee.pk)
    call_command("reencrypt_national_ids")

    # Already-encrypted rows are left untouched, not double-encrypted.
    assert _raw(MenteeKYC, mentee.pk) == first
    assert MenteeKYC.objects.get(pk=mentee.pk).national_id_number == NATIONAL_ID


@pytest.mark.django_db
def test_dry_run_changes_nothing(plaintext_rows, settings):
    mentee, _ = plaintext_rows
    settings.ENCRYPTION_KEY = Fernet.generate_key().decode()

    call_command("reencrypt_national_ids", "--dry-run")

    assert _raw(MenteeKYC, mentee.pk) == NATIONAL_ID


@pytest.mark.django_db
def test_backfill_refuses_to_run_without_a_key(plaintext_rows, settings):
    settings.ENCRYPTION_KEY = ""
    with pytest.raises(CommandError, match="ENCRYPTION_KEY"):
        call_command("reencrypt_national_ids")


@pytest.mark.django_db
def test_backfill_leaves_rows_encrypted_under_a_different_key_alone(plaintext_rows, settings):
    """A value that is a Fernet token we CANNOT decrypt means a key mismatch.

    Re-encrypting it would bury unreadable ciphertext under a second layer and
    destroy any chance of recovery with the right key. It must be reported and
    skipped, never rewritten.
    """
    mentee, _ = plaintext_rows
    settings.ENCRYPTION_KEY = Fernet.generate_key().decode()
    call_command("reencrypt_national_ids")
    under_old_key = _raw(MenteeKYC, mentee.pk)

    settings.ENCRYPTION_KEY = Fernet.generate_key().decode()  # a DIFFERENT key
    call_command("reencrypt_national_ids")

    assert _raw(MenteeKYC, mentee.pk) == under_old_key

"""Encrypt KYC national IDs that were stored in plaintext.

Run ONCE after ENCRYPTION_KEY is first set in an environment:

    python manage.py reencrypt_national_ids --dry-run   # report only
    python manage.py reencrypt_national_ids             # apply

Why this exists: migration 0019 contained this backfill, but it is a no-op when
no key is configured — and that is how it ran in production. Migrations do not
re-run, so after a key is added only NEW writes are encrypted; existing rows stay
plaintext (still readable, because EncryptedCharField tolerates legacy values)
until something re-saves them. This command is that something.

Safe to re-run: rows that already decrypt with the current key are skipped.
"""
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand, CommandError
from django.db.models import TextField
from django.db.models.functions import Cast

from apps.users.models import MenteeKYC, MentorKYC
from core.fields import require_encryption_key

FIELD = "national_id_number"
#: Every Fernet token is url-safe base64 of a payload whose first byte is the
#: version marker 0x80, so the text always begins "gAAAA".
FERNET_PREFIX = "gAAAA"


class Command(BaseCommand):
    help = "Encrypt KYC national IDs left in plaintext from before ENCRYPTION_KEY was set."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Report what would change without writing anything.",
        )

    def handle(self, *args, dry_run=False, **options):
        try:
            key = require_encryption_key(getattr(settings, "ENCRYPTION_KEY", ""))
        except ImproperlyConfigured as exc:
            raise CommandError(str(exc)) from exc
        cipher = Fernet(key.encode())

        totals = {"encrypted": 0, "already": 0, "foreign": 0}
        for model in (MentorKYC, MenteeKYC):
            counts = self._process(model, cipher, dry_run)
            for name, n in counts.items():
                totals[name] += n
            self.stdout.write(
                f"{model.__name__}: {counts['encrypted']} "
                f"{'would be ' if dry_run else ''}encrypted, "
                f"{counts['already']} already encrypted, {counts['foreign']} skipped"
            )

        if totals["foreign"]:
            self.stdout.write(self.style.WARNING(
                f"{totals['foreign']} row(s) hold a Fernet token that the CURRENT key "
                "cannot decrypt — they were encrypted under a different key. Left "
                "untouched: re-encrypting would bury them beyond recovery. Restore the "
                "original ENCRYPTION_KEY to read them."
            ))
        verb = "Dry run — nothing written." if dry_run else "Done."
        self.stdout.write(self.style.SUCCESS(f"{verb} {totals['encrypted']} row(s) "
                                             f"{'need' if dry_run else 'were'} encrypt{'ing' if dry_run else 'ed'}."))

    def _process(self, model, cipher, dry_run):
        counts = {"encrypted": 0, "already": 0, "foreign": 0}
        # Cast() reads the column AS STORED. Selecting the field normally would run
        # EncryptedCharField.from_db_value and hand back decrypted text, making
        # plaintext and ciphertext rows indistinguishable.
        rows = (
            model.objects.exclude(**{FIELD: ""})
            .annotate(_raw=Cast(FIELD, TextField()))
            .values_list("pk", "_raw")
            .iterator()
        )
        for pk, raw in rows:
            if not raw:
                continue
            try:
                cipher.decrypt(raw.encode())
                counts["already"] += 1
                continue
            except (InvalidToken, ValueError):
                pass

            if raw.startswith(FERNET_PREFIX):
                # Looks like ciphertext but this key can't open it: a key mismatch,
                # not plaintext. Never rewrite it.
                counts["foreign"] += 1
                continue

            counts["encrypted"] += 1
            if not dry_run:
                # .update() encrypts via get_prep_value, and deliberately bypasses
                # save(): no signals, no auto_now bump, and no clash with the rule
                # that approved KYC records are immutable. The VALUE is unchanged —
                # only its at-rest representation.
                model.objects.filter(pk=pk).update(**{FIELD: raw})
        return counts

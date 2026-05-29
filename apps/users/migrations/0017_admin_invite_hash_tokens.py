"""Hash admin invite tokens at rest (audit P1 #8).

Drops the raw `token` column and replaces it with `token_hash`. All
existing SENT invites are REVOKED in the same transaction — they become
unusable because the hash for their plaintext can no longer be recovered.
Admins re-issue any that are still needed.

Migration shape:
  1. Revoke pending invites (status sent → revoked).
  2. Add nullable `token_hash` column.
  3. Backfill each row with a random unique hex placeholder.
  4. Drop the raw `token` column.
  5. Make `token_hash` NOT NULL and unique.
"""

import secrets

from django.db import migrations, models


def revoke_pending_invites(apps, schema_editor):
    AdminInvite = apps.get_model("users", "AdminInvite")
    AdminInvite.objects.filter(status="sent").update(status="revoked")


def backfill_token_hash(apps, schema_editor):
    """Give every existing row a unique random hash so we can flip on UNIQUE."""
    AdminInvite = apps.get_model("users", "AdminInvite")
    for invite in AdminInvite.objects.all():
        invite.token_hash = secrets.token_hex(32)  # 64 chars, matches SHA-256 width
        invite.save(update_fields=["token_hash"])


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0016_admin_role_management"),
    ]

    operations = [
        # 1. Invalidate every in-flight invite first.
        migrations.RunPython(revoke_pending_invites, noop_reverse),

        # 2. Add nullable token_hash column (no index yet — step 5 adds the
        #    unique index, which implies + supersedes db_index). Adding
        #    db_index here would race with the AlterField in step 5 and
        #    cause "_like index already exists" on PG.
        migrations.AddField(
            model_name="admininvite",
            name="token_hash",
            field=models.CharField(
                max_length=64,
                null=True,
                editable=False,
            ),
        ),

        # 3. Backfill historical rows with unique random placeholders.
        migrations.RunPython(backfill_token_hash, noop_reverse),

        # 4. Drop the raw token column.
        migrations.RemoveField(
            model_name="admininvite",
            name="token",
        ),

        # 5. Lock down the new column: NOT NULL + UNIQUE. UNIQUE implies an
        #    index — adding db_index here would duplicate it.
        migrations.AlterField(
            model_name="admininvite",
            name="token_hash",
            field=models.CharField(
                max_length=64,
                unique=True,
                editable=False,
            ),
        ),
    ]

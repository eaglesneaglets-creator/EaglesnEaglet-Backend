"""Phase 18-01 — Admin Role Management.

Adds:
  * User.is_platform_staff (boolean)
  * AdminRoleRequest, AdminInvite, AdminRoleAudit models
  * Backfill: every existing user with role='admin' or is_superuser=True
    gets is_platform_staff=True + a granted audit row tagged 'manual',
    so the audit log starts complete.
"""

import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models
from django.db.models import Q

import apps.users.models_admin


def backfill_admin_role(apps, schema_editor):
    """Mark legacy admins and seed the audit trail."""
    User = apps.get_model("users", "User")
    AdminRoleAudit = apps.get_model("users", "AdminRoleAudit")

    legacy_admins = User.objects.filter(
        Q(role="admin") | Q(is_superuser=True)
    )

    for user in legacy_admins.iterator():
        if not user.is_platform_staff:
            user.is_platform_staff = True
            user.save(update_fields=["is_platform_staff"])

        AdminRoleAudit.objects.create(
            id=uuid.uuid4(),
            actor=None,
            target=user,
            action="granted",
            source="manual",
            reason="Backfill: pre-existing admin migrated to is_platform_staff.",
        )


def reverse_backfill(apps, schema_editor):
    """No-op reverse — leave the flag set so we don't lock anyone out."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0015_user_profile_visibility"),
    ]

    operations = [
        # 1. New User flag
        migrations.AddField(
            model_name="user",
            name="is_platform_staff",
            field=models.BooleanField(
                default=False,
                help_text="Whether the user has elevated platform-admin privileges.",
            ),
        ),

        # 2. AdminRoleRequest
        migrations.CreateModel(
            name="AdminRoleRequest",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("reason", models.TextField(
                    help_text="Why the mentor wants to take on admin responsibilities (≥50 chars).",
                    max_length=2000,
                )),
                ("status", models.CharField(
                    choices=[
                        ("pending", "Pending"),
                        ("approved", "Approved"),
                        ("rejected", "Rejected"),
                        ("withdrawn", "Withdrawn"),
                    ],
                    db_index=True,
                    default="pending",
                    max_length=12,
                )),
                ("decided_at", models.DateTimeField(blank=True, null=True)),
                ("decision_note", models.TextField(blank=True, max_length=1000)),
                ("decided_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="admin_role_decisions",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("user", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="admin_role_requests",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "db_table": "admin_role_requests",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="adminrolerequest",
            constraint=models.UniqueConstraint(
                fields=("user",),
                condition=Q(status="pending"),
                name="one_pending_admin_request_per_user",
            ),
        ),

        # 3. AdminInvite
        migrations.CreateModel(
            name="AdminInvite",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("email", models.EmailField(db_index=True, max_length=254)),
                ("token", models.CharField(
                    default=apps.users.models_admin._generate_invite_token,
                    editable=False,
                    max_length=64,
                    unique=True,
                )),
                ("status", models.CharField(
                    choices=[
                        ("sent", "Sent"),
                        ("accepted", "Accepted"),
                        ("expired", "Expired"),
                        ("revoked", "Revoked"),
                    ],
                    db_index=True,
                    default="sent",
                    max_length=12,
                )),
                ("expires_at", models.DateTimeField(default=apps.users.models_admin._invite_default_expiry)),
                ("accepted_at", models.DateTimeField(blank=True, null=True)),
                ("message", models.TextField(blank=True, max_length=500)),
                ("accepted_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="admin_invites_accepted",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("invited_by", models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="admin_invites_sent",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "db_table": "admin_invites",
                "ordering": ["-created_at"],
            },
        ),

        # 4. AdminRoleAudit
        migrations.CreateModel(
            name="AdminRoleAudit",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("action", models.CharField(
                    choices=[
                        ("granted", "Granted"),
                        ("revoked", "Revoked"),
                        ("self_revoked", "Self-revoked"),
                        ("system_revoked", "System-revoked"),
                    ],
                    db_index=True,
                    max_length=20,
                )),
                ("source", models.CharField(
                    choices=[
                        ("eoi", "Expression of Interest"),
                        ("invite", "Direct invite"),
                        ("manual", "Manual (CLI / migration)"),
                        ("system", "System action"),
                    ],
                    max_length=20,
                )),
                ("reason", models.TextField(blank=True, max_length=2000)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("actor", models.ForeignKey(
                    blank=True,
                    help_text="User who performed the action. NULL for system-driven events.",
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("target", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="admin_role_audit_entries",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "db_table": "admin_role_audit",
                "ordering": ["-created_at"],
            },
        ),

        # 5. Backfill
        migrations.RunPython(backfill_admin_role, reverse_backfill),
    ]

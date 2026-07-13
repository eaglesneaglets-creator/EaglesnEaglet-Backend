"""
Management command: create_admin

Bootstrap the platform superadmin from environment variables.
Safe to run on every deploy — idempotent for an existing ADMIN_EMAIL.

Usage:
    python manage.py create_admin
    python manage.py create_admin --reset-password   # apply ADMIN_PASSWORD to existing user

Required env vars:
    ADMIN_EMAIL     - Superadmin email address
    ADMIN_PASSWORD  - Password (used on create, or with --reset-password)

Optional env vars:
    ADMIN_FIRST_NAME  - First name (default: 'Admin')
    ADMIN_LAST_NAME   - Last name (default: 'User')

Admin bootstrap scenarios:
    * New email — creates a superadmin (is_superuser + is_platform_staff) with
      ADMIN_PASSWORD. Email/password login works immediately.
    * Existing Google-only account — create_admin upgrades flags but does NOT
      set a password unless you pass --reset-password. Alternatively the user
      can use Forgot password or a shell ``set_password`` call.
    * Invited platform admins — created via admin-role invites; they receive
      is_platform_staff only (not superuser). Only this bootstrap account is
      the superadmin.
"""

from django.core.management.base import BaseCommand
from decouple import config, UndefinedValueError


class Command(BaseCommand):
    help = (
        "Create or upgrade the bootstrap superadmin from ADMIN_EMAIL / "
        "ADMIN_PASSWORD env vars."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset-password',
            action='store_true',
            help=(
                'Apply ADMIN_PASSWORD to an existing user. Use only when you '
                'intentionally need to reset the bootstrap admin password '
                '(e.g. after OAuth signup or a lost password).'
            ),
        )

    def handle(self, *args, **options):
        from apps.users.models import User

        try:
            email = config('ADMIN_EMAIL')
            password = config('ADMIN_PASSWORD')
        except UndefinedValueError as e:
            self.stderr.write(self.style.ERROR(
                f"Missing required env var: {e}. "
                "Set ADMIN_EMAIL and ADMIN_PASSWORD and try again."
            ))
            return

        first_name = config('ADMIN_FIRST_NAME', default='Admin')
        last_name = config('ADMIN_LAST_NAME', default='User')
        reset_password = options['reset_password']

        self.stdout.write(f"Checking for bootstrap superadmin: {email}")

        existing = User.objects.filter(email=email).first()

        if existing:
            updated = False
            if not existing.is_superuser:
                existing.is_superuser = True
                updated = True
            if not existing.is_staff:
                existing.is_staff = True
                updated = True
            if not existing.is_platform_staff:
                existing.is_platform_staff = True
                updated = True
            if not existing.is_email_verified:
                existing.is_email_verified = True
                updated = True
            if existing.role != User.Role.ADMIN:
                existing.role = User.Role.ADMIN
                updated = True
            if existing.status != User.Status.ACTIVE:
                existing.status = User.Status.ACTIVE
                updated = True

            if reset_password:
                existing.set_password(password)
                updated = True
                self.stdout.write(self.style.WARNING(
                    f"Password reset applied for '{email}' from ADMIN_PASSWORD."
                ))

            if updated:
                existing.save()
                self.stdout.write(self.style.SUCCESS(
                    f"Existing user '{email}' updated to bootstrap superadmin."
                ))
            else:
                self.stdout.write(self.style.WARNING(
                    f"Superadmin '{email}' already exists with correct privileges — skipping."
                ))
            return

        User.objects.create_superuser(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )

        self.stdout.write(self.style.SUCCESS(
            f"Bootstrap superadmin '{email}' created successfully."
        ))

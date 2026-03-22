"""
Management command: create_admin

Creates the initial admin user from environment variables.
Safe to run multiple times — skips creation if the email already exists.

Usage:
    python manage.py create_admin

Required env vars:
    ADMIN_EMAIL     - Admin email address
    ADMIN_PASSWORD  - Admin password

Optional env vars:
    ADMIN_FIRST_NAME  - First name (default: 'Admin')
    ADMIN_LAST_NAME   - Last name (default: 'User')
"""

from django.core.management.base import BaseCommand
from decouple import config, UndefinedValueError


class Command(BaseCommand):
    help = "Create the initial admin user from ADMIN_EMAIL and ADMIN_PASSWORD env vars."

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

        self.stdout.write(f"Checking for admin user: {email}")

        existing = User.objects.filter(email=email).first()

        if existing:
            # User exists — ensure they have full admin privileges
            updated = False
            if not existing.is_superuser:
                existing.is_superuser = True
                updated = True
            if not existing.is_staff:
                existing.is_staff = True
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

            if updated:
                existing.save()
                self.stdout.write(self.style.SUCCESS(
                    f"Existing user '{email}' updated to full admin privileges."
                ))
            else:
                self.stdout.write(self.style.WARNING(
                    f"Admin '{email}' already exists with correct privileges — skipping."
                ))
            return

        User.objects.create_superuser(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )

        self.stdout.write(self.style.SUCCESS(
            f"Admin user '{email}' created successfully."
        ))

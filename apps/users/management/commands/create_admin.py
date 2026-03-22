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

        if User.objects.filter(email=email).exists():
            self.stdout.write(self.style.WARNING(
                f"Admin with email '{email}' already exists — skipping."
            ))
            return

        first_name = config('ADMIN_FIRST_NAME', default='Admin')
        last_name = config('ADMIN_LAST_NAME', default='User')

        User.objects.create_superuser(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )

        self.stdout.write(self.style.SUCCESS(
            f"Admin user '{email}' created successfully."
        ))

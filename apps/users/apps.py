from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'
    verbose_name = 'Users & Authentication'

    def ready(self):
        # Register signals (auto-Nest on mentor approval — plan 14.5-01).
        from . import signals  # noqa: F401
        # Admin-role auto-revoke on account suspension (plan 18-01).
        from . import signals_admin  # noqa: F401

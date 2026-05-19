from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'
    verbose_name = 'Users & Authentication'

    def ready(self):
        # Register signals (auto-Nest on mentor approval — plan 14.5-01).
        from . import signals  # noqa: F401

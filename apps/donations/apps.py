from django.apps import AppConfig


class DonationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.donations'
    verbose_name = 'Donations'

    def ready(self):
        import apps.donations.signals  # noqa: F401

from django.apps import AppConfig


class StoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.store'
    verbose_name = 'E-Commerce Store'

    def ready(self):
        import apps.store.signals  # noqa: F401

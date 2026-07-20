from django.apps import AppConfig


class NestsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.nests'
    verbose_name = 'Nests (Mentor Communities)'

    def ready(self):
        # Wire signals (plan 14-02): mirror ProgramEnrollment status onto
        # NestMembership so existing community-access code keeps working.
        from . import signals  # noqa: F401

        # Phase 27-01: NestActivity audit model + its recording signals.
        # Importing here guarantees the model is registered at app-ready.
        from . import models_activity  # noqa: F401
        from . import signals_activity  # noqa: F401

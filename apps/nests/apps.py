from django.apps import AppConfig


class NestsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.nests'
    verbose_name = 'Nests (Mentor Communities)'

    def ready(self):
        # Wire signals (plan 14-02): mirror ProgramEnrollment status onto
        # NestMembership so existing community-access code keeps working.
        from . import signals  # noqa: F401

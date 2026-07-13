"""Remove Django is_staff from invited platform admins (non-superusers)."""

from django.db import migrations


def demote_invited_admin_staff(apps, schema_editor):
    User = apps.get_model('users', 'User')
    User.objects.filter(
        is_platform_staff=True,
        is_superuser=False,
        is_staff=True,
    ).update(is_staff=False)


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0021_timezone_default_accra'),
    ]

    operations = [
        migrations.RunPython(demote_invited_admin_staff, migrations.RunPython.noop),
    ]

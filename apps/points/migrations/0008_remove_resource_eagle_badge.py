"""
Remove deprecated 'Resource Eagle' (first_resource_share) badge.

Badges are Eaglet-only; this one-time badge was tied to Eagle resource uploads
and is no longer awarded. Deletes any earned UserBadge rows first, then the
Badge record. seed_badges / 0007 history are left intact for audit; 0008 cleans
deployed databases.
"""

from django.db import migrations

SLUG = "first_resource_share"


def remove_resource_eagle_badge(apps, schema_editor):
    Badge = apps.get_model("points", "Badge")
    UserBadge = apps.get_model("points", "UserBadge")

    badge_ids = list(
        Badge.objects.filter(slug=SLUG).values_list("pk", flat=True)
    )
    if not badge_ids:
        return

    UserBadge.objects.filter(badge_id__in=badge_ids).delete()
    Badge.objects.filter(pk__in=badge_ids).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("points", "0007_seed_badges"),
    ]

    operations = [
        migrations.RunPython(
            remove_resource_eagle_badge,
            reverse_code=migrations.RunPython.noop,
        ),
    ]

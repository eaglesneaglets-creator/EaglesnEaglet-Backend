"""Raise mentee level thresholds (user request, post plan 14-04).

Old thresholds (0/100/300/750/1500) gamified far too easily — eaglets hit
Level 5 with minimal program engagement, defeating the mentor-eligibility
gate. New thresholds raise the bar so each level reflects meaningful
program progress.

This migration only updates rows that still hold the OLD default values.
If an admin has already customized a row via the admin endpoint, we leave
it alone — no surprise overwrites of operator config.

Reverse: restores the old default thresholds for rows that match the new
defaults (same anti-surprise rule).
"""

from django.db import migrations


# (level, name, new_points_required, old_points_required)
LEVEL_BUMPS = [
    (1, "Hatchling",      500,  0),
    (2, "Fledgling",     1000,  100),
    (3, "Flyer",         1500,  300),
    (4, "Soaring",       2000,  750),
    (5, "Master Eagle",  3000,  1500),
]


def raise_thresholds(apps, schema_editor):
    MenteeLevelConfig = apps.get_model("nests", "MenteeLevelConfig")
    for level, name, new_pts, old_pts in LEVEL_BUMPS:
        MenteeLevelConfig.objects.filter(
            level=level, name=name, points_required=old_pts,
        ).update(points_required=new_pts)


def lower_thresholds(apps, schema_editor):
    MenteeLevelConfig = apps.get_model("nests", "MenteeLevelConfig")
    for level, name, new_pts, old_pts in LEVEL_BUMPS:
        MenteeLevelConfig.objects.filter(
            level=level, name=name, points_required=new_pts,
        ).update(points_required=old_pts)


class Migration(migrations.Migration):

    dependencies = [
        ("nests", "0010_seed_default_levels"),
    ]

    operations = [
        migrations.RunPython(raise_thresholds, lower_thresholds),
    ]

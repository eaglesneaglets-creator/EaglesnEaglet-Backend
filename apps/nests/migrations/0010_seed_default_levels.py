"""Seed default 5-tier MenteeLevelConfig rows (plan 14-04).

Reverse: deletes only rows whose name matches the default — keeps any custom edits.
"""

from django.db import migrations


DEFAULT_LEVELS = [
    {"level": 1, "name": "Hatchling", "points_required": 0,
     "unlocks_mentor_application": False,
     "description": "Just joined a program."},
    {"level": 2, "name": "Fledgling", "points_required": 100,
     "unlocks_mentor_application": False,
     "description": "Building early momentum."},
    {"level": 3, "name": "Flyer", "points_required": 300,
     "unlocks_mentor_application": False,
     "description": "Consistent progress and engagement."},
    {"level": 4, "name": "Soaring", "points_required": 750,
     "unlocks_mentor_application": False,
     "description": "Demonstrated mastery in a program."},
    {"level": 5, "name": "Master Eagle", "points_required": 1500,
     "unlocks_mentor_application": True,
     "description": "Eligible to apply to become a mentor."},
]


def seed_levels(apps, schema_editor):
    MenteeLevelConfig = apps.get_model("nests", "MenteeLevelConfig")
    for row in DEFAULT_LEVELS:
        MenteeLevelConfig.objects.update_or_create(
            level=row["level"],
            defaults={
                "name": row["name"],
                "points_required": row["points_required"],
                "unlocks_mentor_application": row["unlocks_mentor_application"],
                "description": row["description"],
            },
        )


def unseed_levels(apps, schema_editor):
    MenteeLevelConfig = apps.get_model("nests", "MenteeLevelConfig")
    for row in DEFAULT_LEVELS:
        MenteeLevelConfig.objects.filter(
            level=row["level"], name=row["name"],
        ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("nests", "0009_mentee_level_config"),
    ]

    operations = [
        migrations.RunPython(seed_levels, unseed_levels),
    ]

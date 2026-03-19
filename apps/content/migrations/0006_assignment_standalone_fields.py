"""
Migration 0006 — Transform Assignment into a standalone, nest-scoped entity.

Changes:
- Make Assignment.module nullable (was required FK)
- Add Assignment.assignment_type (default "standalone")
- Add Assignment.nest FK (nullable)
- Add Assignment.created_by FK (nullable)
- Data migration: set all existing rows to assignment_type="standalone"
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def set_existing_assignment_type(apps, schema_editor):
    Assignment = apps.get_model("content", "Assignment")
    Assignment.objects.all().update(assignment_type="standalone")


class Migration(migrations.Migration):

    dependencies = [
        ("content", "0005_remove_contentmodule_module_type"),
        ("nests", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # 1. Make module nullable
        migrations.AlterField(
            model_name="assignment",
            name="module",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="assignments",
                to="content.contentmodule",
            ),
        ),
        # 2. Add assignment_type
        migrations.AddField(
            model_name="assignment",
            name="assignment_type",
            field=models.CharField(
                choices=[("standalone", "Standalone")],
                default="standalone",
                max_length=15,
            ),
        ),
        # 3. Add nest FK
        migrations.AddField(
            model_name="assignment",
            name="nest",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="standalone_assignments",
                to="nests.nest",
            ),
        ),
        # 4. Add created_by FK
        migrations.AddField(
            model_name="assignment",
            name="created_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="created_assignments",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        # 5. Data migration
        migrations.RunPython(
            set_existing_assignment_type,
            reverse_code=migrations.RunPython.noop,
        ),
    ]

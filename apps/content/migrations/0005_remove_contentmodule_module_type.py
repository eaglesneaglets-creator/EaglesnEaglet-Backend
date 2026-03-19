"""
Migration 0005 — Remove module_type field from ContentModule.

The module_type field conflated "assignment vs resource" with module
creation. Modules are now plain containers; quiz attachment determines
whether completion requires a quiz pass.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("content", "0004_contentmodule_thumbnail_url"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="contentmodule",
            name="module_type",
        ),
    ]

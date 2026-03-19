"""
Migration 0007 — Add ModuleAssignment, ModuleQuestion, ModuleAssignmentAttempt.

These models power the MCQ + descriptive quiz system that gates module
completion. A ContentModule can have at most one ModuleAssignment (OneToOne).
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("content", "0006_assignment_standalone_fields"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ModuleAssignment",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("title", models.CharField(max_length=200)),
                ("pass_score", models.IntegerField(default=60, help_text="Minimum MCQ % to pass.")),
                ("max_attempts", models.IntegerField(default=3)),
                ("points_value", models.IntegerField(default=50)),
                (
                    "module",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="quiz",
                        to="content.contentmodule",
                    ),
                ),
            ],
            options={"db_table": "module_assignments"},
        ),
        migrations.CreateModel(
            name="ModuleQuestion",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("question_type", models.CharField(
                    choices=[("mcq", "Multiple Choice"), ("descriptive", "Descriptive")],
                    max_length=15,
                )),
                ("question_text", models.TextField()),
                ("options", models.JSONField(
                    blank=True, null=True,
                    help_text='["opt A", "opt B", "opt C", "opt D"] for MCQ',
                )),
                ("correct_option", models.IntegerField(
                    blank=True, null=True,
                    help_text="0-3 index of the correct option (MCQ only).",
                )),
                ("order", models.IntegerField(default=0)),
                (
                    "assignment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="questions",
                        to="content.moduleassignment",
                    ),
                ),
            ],
            options={"db_table": "module_questions", "ordering": ["order"]},
        ),
        migrations.CreateModel(
            name="ModuleAssignmentAttempt",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("answers", models.JSONField(help_text='{"<question_id>": answer_index_or_text}')),
                ("score", models.IntegerField(
                    blank=True, null=True,
                    help_text="MCQ percentage score (0-100). Null if no MCQ questions.",
                )),
                ("passed", models.BooleanField(default=False)),
                ("attempt_number", models.IntegerField()),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "assignment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="attempts",
                        to="content.moduleassignment",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="module_attempts",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "module_assignment_attempts",
                "ordering": ["-attempt_number"],
            },
        ),
        migrations.AddConstraint(
            model_name="moduleassignmentattempt",
            constraint=models.UniqueConstraint(
                fields=["assignment", "user", "attempt_number"],
                name="unique_attempt_per_user_quiz",
            ),
        ),
    ]

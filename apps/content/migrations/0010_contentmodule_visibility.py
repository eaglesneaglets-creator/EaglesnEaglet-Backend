from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("content", "0009_remove_moduleassignmentattempt_unique_attempt_per_user_quiz_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="contentmodule",
            name="visibility",
            field=models.CharField(
                choices=[("all_mentees", "All Mentees"), ("nest_only", "Nest Only")],
                default="nest_only",
                help_text="all_mentees: appears in Resource Center. nest_only: appears in Assignments/Learning Modules.",
                max_length=15,
            ),
        ),
    ]

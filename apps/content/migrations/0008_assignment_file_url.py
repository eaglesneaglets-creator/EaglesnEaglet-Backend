from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("content", "0007_module_quiz_models"),
    ]

    operations = [
        migrations.AddField(
            model_name="assignment",
            name="file_url",
            field=models.URLField(blank=True, default="", max_length=1000),
        ),
    ]

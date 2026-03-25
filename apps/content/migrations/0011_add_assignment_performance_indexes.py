from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('content', '0010_contentmodule_visibility'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='assignment',
            index=models.Index(fields=['nest', 'assignment_type'], name='assignment_nest_type_idx'),
        ),
        migrations.AddIndex(
            model_name='assignment',
            index=models.Index(fields=['nest', 'created_by'], name='assignment_nest_creator_idx'),
        ),
    ]

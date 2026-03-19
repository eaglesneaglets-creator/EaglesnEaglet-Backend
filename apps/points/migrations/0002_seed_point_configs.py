from django.db import migrations

def seed_point_configs(apps, schema_editor):
    PointConfiguration = apps.get_model("points", "PointConfiguration")
    
    configs = [
        ("video_complete", "Video Completed", 20),
        ("document_read", "Document Read", 10),
        ("assignment_submit", "Assignment Submitted", 50),
        ("assignment_graded", "Assignment Graded", 100),
        ("module_complete", "Module Completed", 200),
        ("check_in", "Daily Check-In", 10),
        ("post_created", "Post Created", 5),
        ("resource_shared", "Resource Shared", 15),
        ("event_attended", "Event Attended", 30),
    ]
    
    for activity_type, name, value in configs:
        PointConfiguration.objects.get_or_create(
            activity_type=activity_type,
            defaults={
                "points_value": value,
                "is_active": True,
                "description": f"Points earned for {name.lower()}"
            }
        )

def remove_point_configs(apps, schema_editor):
    PointConfiguration = apps.get_model("points", "PointConfiguration")
    PointConfiguration.objects.all().delete()

class Migration(migrations.Migration):
    dependencies = [
        ("points", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_point_configs, remove_point_configs),
    ]

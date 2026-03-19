import os
import django
import sys

# Add the project root and backend root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)
sys.path.append(os.path.join(BASE_DIR, 'eaglesneagletsbackend'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eaglesneagletsbackend.settings.local')

try:
    django.setup()
    from apps.points.models import PointConfiguration
    
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
    
    print("Seeding Point Configurations...")
    for activity_type, name, value in configs:
        obj, created = PointConfiguration.objects.get_or_create(
            activity_type=activity_type,
            defaults={
                "points_value": value,
                "is_active": True,
                "description": f"Points earned for {name.lower()}"
            }
        )
        if created:
            print(f"  [CREATED] {activity_type}: {value}pts")
        else:
            print(f"  [EXISTS] {activity_type}")
            if not obj.is_active:
                obj.is_active = True
                obj.save()
                print(f"    - Activated existing config.")

    print("\nCheck-in configuration fix complete.")

except Exception as e:
    print(f"Error during seeding: {e}")
    import traceback
    traceback.print_exc()

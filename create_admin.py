import os
import django
from django.utils import timezone

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eaglesneagletsbackend.settings.local')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

EMAIL = 'danieloppong757@gmail.com'
PASSWORD = '12345@0011.'
FIRST = 'Daniel'
LAST = 'Oppong'

existing = User.objects.filter(email=EMAIL).first()
if existing:
    existing.first_name = FIRST
    existing.last_name = LAST
    existing.role = 'admin'
    existing.is_staff = True
    existing.is_superuser = True
    existing.is_active = True
    existing.is_email_verified = True
    existing.status = 'active'
    existing.set_password(PASSWORD)
    existing.password_changed_at = timezone.now()
    existing.save()
    print(f'UPDATED: {existing.email} (id={existing.id})')
else:
    user = User.objects.create_superuser(
        email=EMAIL,
        password=PASSWORD,
        first_name=FIRST,
        last_name=LAST,
    )
    user.role = 'admin'
    user.is_email_verified = True
    user.status = 'active'
    user.save()
    print(f'CREATED: {user.email} (id={user.id})')

from apps.users.models import User
from django.db import transaction

def create_test_user(email, password, role, first_name, last_name):
    with transaction.atomic():
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'first_name': first_name,
                'last_name': last_name,
                'role': role,
                'is_email_verified': True,
                'status': User.Status.ACTIVE,
                'is_active': True
            }
        )
        if created:
            user.set_password(password)
            user.save()
            print(f"Created user: {email}")
        else:
            user.is_email_verified = True
            user.status = User.Status.ACTIVE
            user.is_active = True
            user.set_password(password)
            user.save()
            print(f"Updated user: {email}")
        return user

# Create Eaglet
create_test_user('test_eaglet@example.com', 'TestPass123!', User.Role.EAGLET, 'Test', 'Eaglet')

# Create Eagle
create_test_user('test_eagle@example.com', 'TestPass123!', User.Role.EAGLE, 'Test', 'Eagle')

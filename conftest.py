"""
Pytest configuration and shared fixtures for Eagles & Eaglets backend.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


@pytest.fixture
def api_client():
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def user_factory(db):
    """Factory for creating test users."""
    def create_user(
        email='test@example.com',
        password='TestPass123!',
        first_name='Test',
        last_name='User',
        role='eaglet',
        is_active=True,
        is_email_verified=True,
        **kwargs
    ):
        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role=role,
            **kwargs
        )
        user.is_active = is_active
        user.is_email_verified = is_email_verified
        user.save()
        return user
    return create_user


@pytest.fixture
def eagle_user(user_factory):
    """Create a verified Eagle (Mentor) user."""
    return user_factory(
        email='eagle@test.com',
        first_name='Eagle',
        last_name='Mentor',
        role='eagle',
    )


@pytest.fixture
def eaglet_user(user_factory):
    """Create a verified Eaglet (Mentee) user."""
    return user_factory(
        email='eaglet@test.com',
        first_name='Eaglet',
        last_name='Mentee',
        role='eaglet',
    )


@pytest.fixture
def admin_user(user_factory):
    """Create an admin user."""
    return user_factory(
        email='admin@test.com',
        first_name='Admin',
        last_name='User',
        role='admin',
    )


@pytest.fixture
def unverified_user(user_factory):
    """Create an unverified user."""
    return user_factory(
        email='unverified@test.com',
        is_email_verified=False,
    )


@pytest.fixture
def authenticated_client(api_client, eagle_user):
    """Return an authenticated API client for Eagle user."""
    refresh = RefreshToken.for_user(eagle_user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return api_client


@pytest.fixture
def eaglet_client(api_client, eaglet_user):
    """Return an authenticated API client for Eaglet user."""
    refresh = RefreshToken.for_user(eaglet_user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return api_client


@pytest.fixture
def admin_client(api_client, admin_user):
    """Return an authenticated API client for Admin user."""
    refresh = RefreshToken.for_user(admin_user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return api_client


@pytest.fixture
def mentor_kyc_data():
    """Return valid mentor KYC data."""
    return {
        'location': 'Accra, Ghana',
        'phone_number': '+233201234567',
        'national_id_number': 'GHA-1234567890',
        'marital_status': 'single',
        'employment_status': 'employed',
        'profile_description': 'I am an experienced mentor with over 10 years of experience in technology and leadership. ' * 3,
        'mentorship_types': ['career_growth', 'leadership', 'technology'],
    }


@pytest.fixture
def mentee_kyc_data():
    """Return valid mentee KYC data."""
    return {
        'national_id_number': 'GHA-9876543210',
        'marital_status': 'single',
        'country': 'Ghana',
        'city': 'Accra',
        'location': 'East Legon',
        'phone_number': '+233209876543',
        'employment_status': 'student',
        'linkedin_url': 'https://linkedin.com/in/testuser',
        'bio': 'I am an enthusiastic learner seeking mentorship to grow my career and skills. ' * 2,
        'mentorship_types': ['career_growth', 'personal_development'],
    }


@pytest.fixture
def mentor_kyc(eagle_user, mentor_kyc_data):
    """Create a MentorKYC record for testing."""
    from apps.users.models import MentorKYC

    kyc = MentorKYC.objects.create(
        user=eagle_user,
        **mentor_kyc_data
    )
    return kyc


@pytest.fixture
def mentee_kyc(eaglet_user, mentee_kyc_data):
    """Create a MenteeKYC record for testing."""
    from apps.users.models import MenteeKYC

    kyc = MenteeKYC.objects.create(
        user=eaglet_user,
        **mentee_kyc_data
    )
    return kyc


@pytest.fixture
def submitted_mentor_kyc(mentor_kyc):
    """Create a submitted MentorKYC for admin review testing."""
    mentor_kyc.status = 'submitted'
    mentor_kyc.display_picture = 'test_picture.jpg'
    mentor_kyc.cv = 'test_cv.pdf'
    mentor_kyc.save()
    return mentor_kyc


@pytest.fixture
def submitted_mentee_kyc(mentee_kyc):
    """Create a submitted MenteeKYC for admin review testing."""
    mentee_kyc.status = 'submitted'
    mentee_kyc.display_picture = 'test_picture.jpg'
    mentee_kyc.save()
    return mentee_kyc

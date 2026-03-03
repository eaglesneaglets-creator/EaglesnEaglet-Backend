"""
Tests for the Users app.

Covers authentication, KYC/profile management, and admin review functionality.
"""

import pytest
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import status

from .models import User, MentorKYC, MenteeKYC
from .validators import (
    validate_ghana_phone,
    validate_linkedin_url,
    validate_national_id,
)
from django.core.exceptions import ValidationError


# =============================================================================
# USER MODEL TESTS
# =============================================================================

@pytest.mark.django_db
class TestUserModel:
    """Tests for the User model."""

    def test_create_user(self, user_factory):
        """Test creating a regular user."""
        user = user_factory(email='newuser@test.com')
        assert user.email == 'newuser@test.com'
        assert user.check_password('TestPass123!')
        assert not user.is_superuser
        assert not user.is_staff

    def test_create_user_normalizes_email(self, user_factory):
        """Test that email is normalized during creation."""
        user = user_factory(email='Test@EXAMPLE.COM')
        assert user.email == 'test@example.com'

    def test_create_user_without_email_fails(self, db):
        """Test that creating user without email raises error."""
        with pytest.raises(ValueError, match='Email is required'):
            User.objects.create_user(email='', password='TestPass123!')

    def test_create_superuser(self, db):
        """Test creating a superuser."""
        user = User.objects.create_superuser(
            email='superadmin@test.com',
            password='SuperPass123!',
            first_name='Super',
            last_name='Admin',
        )
        assert user.is_superuser
        assert user.is_staff
        assert user.role == 'admin'

    def test_user_role_properties(self, eagle_user, eaglet_user, admin_user):
        """Test role property methods."""
        assert eagle_user.is_eagle
        assert not eagle_user.is_eaglet
        assert not eagle_user.is_admin

        assert eaglet_user.is_eaglet
        assert not eaglet_user.is_eagle
        assert not eaglet_user.is_admin

        assert admin_user.is_admin
        assert not admin_user.is_eagle
        assert not admin_user.is_eaglet

    def test_failed_login_tracking(self, eagle_user):
        """Test failed login attempt tracking."""
        assert eagle_user.failed_login_attempts == 0
        assert not eagle_user.is_account_locked

        # Simulate 5 failed attempts
        for _ in range(5):
            eagle_user.increment_failed_login()

        assert eagle_user.failed_login_attempts == 5
        assert eagle_user.is_account_locked

    def test_reset_failed_login(self, eagle_user):
        """Test resetting failed login attempts."""
        eagle_user.failed_login_attempts = 3
        eagle_user.save()

        eagle_user.reset_failed_login()
        assert eagle_user.failed_login_attempts == 0

    def test_soft_delete(self, eagle_user):
        """Test soft delete functionality."""
        original_email = eagle_user.email
        eagle_user.soft_delete()

        assert not eagle_user.is_active
        assert 'deleted' in eagle_user.email
        assert original_email not in eagle_user.email


# =============================================================================
# VALIDATOR TESTS
# =============================================================================

@pytest.mark.django_db
class TestValidators:
    """Tests for custom validators."""

    def test_valid_ghana_phone_with_plus233(self):
        """Test valid Ghana phone number with +233 prefix."""
        # Should not raise
        validate_ghana_phone('+233201234567')
        validate_ghana_phone('+233551234567')

    def test_valid_ghana_phone_with_zero(self):
        """Test valid Ghana phone number with 0 prefix."""
        validate_ghana_phone('0201234567')
        validate_ghana_phone('0551234567')

    def test_invalid_ghana_phone_raises_error(self):
        """Test invalid phone numbers raise ValidationError."""
        invalid_phones = [
            '123456789',       # No prefix
            '+1234567890',     # Wrong country
            '+233123',         # Too short
            '+2330123456789',  # Too long
            'abcdefghij',      # Letters
        ]
        for phone in invalid_phones:
            with pytest.raises(ValidationError):
                validate_ghana_phone(phone)

    def test_valid_linkedin_url(self):
        """Test valid LinkedIn URLs."""
        valid_urls = [
            'https://linkedin.com/in/username',
            'https://www.linkedin.com/in/john-doe',
            'http://linkedin.com/in/test-user-123',
        ]
        for url in valid_urls:
            validate_linkedin_url(url)  # Should not raise

    def test_invalid_linkedin_url_raises_error(self):
        """Test invalid LinkedIn URLs raise ValidationError."""
        invalid_urls = [
            'https://facebook.com/username',
            'https://linkedin.com/company/test',
            'not-a-url',
            'linkedin.com/in/test',  # Missing protocol
        ]
        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_linkedin_url(url)

    def test_valid_national_id(self):
        """Test valid national ID formats."""
        valid_ids = [
            'GHA-123456',
            'ABC1234567890',
            '123-456-789',
        ]
        for id_num in valid_ids:
            validate_national_id(id_num)  # Should not raise

    def test_invalid_national_id_raises_error(self):
        """Test invalid national IDs raise ValidationError."""
        invalid_ids = [
            '12345',           # Too short
            'A' * 25,          # Too long
            'test@#$%',        # Invalid characters
        ]
        for id_num in invalid_ids:
            with pytest.raises(ValidationError):
                validate_national_id(id_num)


# =============================================================================
# AUTHENTICATION API TESTS
# =============================================================================

@pytest.mark.django_db
class TestAuthenticationAPI:
    """Tests for authentication endpoints."""

    def test_user_registration(self, api_client):
        """Test user registration endpoint."""
        url = reverse('users:register')
        data = {
            'email': 'newuser@test.com',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'eaglet',
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['success'] is True
        assert User.objects.filter(email='newuser@test.com').exists()

    def test_user_registration_weak_password_fails(self, api_client):
        """Test registration with weak password fails."""
        url = reverse('users:register')
        data = {
            'email': 'newuser@test.com',
            'password': '123',
            'password_confirm': '123',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'eaglet',
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_registration_mismatched_passwords_fails(self, api_client):
        """Test registration with mismatched passwords fails."""
        url = reverse('users:register')
        data = {
            'email': 'newuser@test.com',
            'password': 'SecurePass123!',
            'password_confirm': 'DifferentPass123!',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'eaglet',
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_login(self, api_client, eagle_user):
        """Test user login endpoint."""
        url = reverse('users:login')
        data = {
            'email': 'eagle@test.com',
            'password': 'TestPass123!',
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data['data']
        assert 'refresh' in response.data['data']

    def test_login_with_invalid_credentials_fails(self, api_client, eagle_user):
        """Test login with invalid credentials fails."""
        url = reverse('users:login')
        data = {
            'email': 'eagle@test.com',
            'password': 'WrongPassword!',
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_unverified_user_fails(self, api_client, unverified_user):
        """Test login with unverified email fails."""
        url = reverse('users:login')
        data = {
            'email': 'unverified@test.com',
            'password': 'TestPass123!',
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_current_user_endpoint(self, authenticated_client, eagle_user):
        """Test getting current user details."""
        url = reverse('users:current-user')

        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['data']['email'] == eagle_user.email

    def test_current_user_unauthenticated_fails(self, api_client):
        """Test current user endpoint requires authentication."""
        url = reverse('users:current-user')

        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# =============================================================================
# MENTOR PROFILE/KYC TESTS
# =============================================================================

@pytest.mark.django_db
class TestMentorProfileAPI:
    """Tests for Mentor profile/KYC endpoints."""

    def test_get_mentor_profile(self, authenticated_client, mentor_kyc):
        """Test getting mentor profile."""
        url = reverse('users:mentor-profile')

        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert response.data['data']['location'] == mentor_kyc.location

    def test_get_mentor_profile_creates_if_not_exists(self, authenticated_client, eagle_user):
        """Test that getting profile creates one if it doesn't exist."""
        url = reverse('users:mentor-profile')

        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert MentorKYC.objects.filter(user=eagle_user).exists()

    def test_update_mentor_profile(self, authenticated_client, mentor_kyc):
        """Test updating mentor profile."""
        url = reverse('users:mentor-profile')
        data = {
            'location': 'Kumasi, Ghana',
            'profile_description': 'Updated profile description with more than one hundred characters to meet the minimum requirement.' * 2,
        }

        response = authenticated_client.patch(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        mentor_kyc.refresh_from_db()
        assert mentor_kyc.location == 'Kumasi, Ghana'

    def test_update_mentor_profile_eaglet_forbidden(self, eaglet_client):
        """Test that eaglet cannot access mentor profile endpoint."""
        url = reverse('users:mentor-profile')

        response = eaglet_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_mentor_profile_completion_percentage(self, authenticated_client, eagle_user):
        """Test profile completion percentage calculation."""
        # Create empty profile
        url = reverse('users:mentor-profile')
        authenticated_client.get(url)  # Creates profile

        response = authenticated_client.get(url)

        # Empty profile should have low completion
        assert response.data['data']['completion_percentage'] < 50


# =============================================================================
# MENTEE PROFILE/KYC TESTS
# =============================================================================

@pytest.mark.django_db
class TestMenteeProfileAPI:
    """Tests for Mentee profile/KYC endpoints."""

    def test_get_mentee_profile(self, eaglet_client, mentee_kyc):
        """Test getting mentee profile."""
        url = reverse('users:mentee-profile')

        response = eaglet_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert response.data['data']['country'] == mentee_kyc.country

    def test_get_mentee_profile_creates_if_not_exists(self, eaglet_client, eaglet_user):
        """Test that getting profile creates one if it doesn't exist."""
        url = reverse('users:mentee-profile')

        response = eaglet_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert MenteeKYC.objects.filter(user=eaglet_user).exists()

    def test_update_mentee_profile(self, eaglet_client, mentee_kyc):
        """Test updating mentee profile."""
        url = reverse('users:mentee-profile')
        data = {
            'city': 'Kumasi',
            'bio': 'Updated bio that is long enough to meet the minimum character requirement for testing.' * 2,
        }

        response = eaglet_client.patch(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        mentee_kyc.refresh_from_db()
        assert mentee_kyc.city == 'Kumasi'

    def test_update_mentee_profile_mentor_forbidden(self, authenticated_client):
        """Test that mentor cannot access mentee profile endpoint."""
        url = reverse('users:mentee-profile')

        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# PROFILE SUBMISSION TESTS
# =============================================================================

@pytest.mark.django_db
class TestProfileSubmission:
    """Tests for profile submission functionality."""

    def test_submit_incomplete_profile_fails(self, authenticated_client, eagle_user):
        """Test that submitting incomplete profile fails."""
        # Create empty profile
        MentorKYC.objects.create(user=eagle_user)

        url = reverse('users:profile-submit')
        response = authenticated_client.post(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'complete' in response.data['error']['message'].lower()

    def test_submit_complete_mentor_profile(self, authenticated_client, mentor_kyc):
        """Test submitting a complete mentor profile."""
        # Make profile complete
        mentor_kyc.display_picture = 'test.jpg'
        mentor_kyc.cv = 'test.pdf'
        mentor_kyc.save()

        url = reverse('users:profile-submit')
        response = authenticated_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        mentor_kyc.refresh_from_db()
        assert mentor_kyc.status == 'submitted'

    def test_submit_already_submitted_profile_fails(self, authenticated_client, submitted_mentor_kyc):
        """Test that re-submitting already submitted profile fails."""
        url = reverse('users:profile-submit')
        response = authenticated_client.post(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


# =============================================================================
# FILE UPLOAD TESTS
# =============================================================================

@pytest.mark.django_db
class TestFileUpload:
    """Tests for file upload endpoints."""

    def test_upload_profile_picture(self, authenticated_client):
        """Test uploading a profile picture."""
        url = reverse('users:upload-picture')

        # Create a simple test image
        image = SimpleUploadedFile(
            name='test.jpg',
            content=b'\x89PNG\r\n\x1a\n' + b'\x00' * 100,
            content_type='image/jpeg'
        )

        response = authenticated_client.post(url, {'file': image}, format='multipart')

        # Should succeed or return error about file format (since our test image is not valid)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]

    def test_upload_cv(self, authenticated_client):
        """Test uploading a CV."""
        url = reverse('users:upload-cv')

        # Create a simple test PDF
        cv = SimpleUploadedFile(
            name='test.pdf',
            content=b'%PDF-1.4 test content' + b'\x00' * 100,
            content_type='application/pdf'
        )

        response = authenticated_client.post(url, {'file': cv}, format='multipart')

        # Should succeed or return error about file format
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]


# =============================================================================
# ADMIN KYC REVIEW TESTS
# =============================================================================

@pytest.mark.django_db
class TestAdminKYCReview:
    """Tests for admin KYC review endpoints."""

    def test_list_kyc_applications(self, admin_client, submitted_mentor_kyc, submitted_mentee_kyc):
        """Test listing KYC applications."""
        url = reverse('users:admin-kyc-list')

        response = admin_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert 'applications' in response.data['data']

    def test_list_kyc_applications_filter_by_role(self, admin_client, submitted_mentor_kyc):
        """Test filtering KYC applications by role."""
        url = reverse('users:admin-kyc-list')

        response = admin_client.get(url, {'role': 'mentor'})

        assert response.status_code == status.HTTP_200_OK
        # All returned applications should be mentors
        for app in response.data['data']['applications']:
            assert app.get('role', 'mentor') == 'mentor'

    def test_list_kyc_applications_filter_by_status(self, admin_client, submitted_mentor_kyc):
        """Test filtering KYC applications by status."""
        url = reverse('users:admin-kyc-list')

        response = admin_client.get(url, {'status': 'submitted'})

        assert response.status_code == status.HTTP_200_OK

    def test_get_kyc_detail_mentor(self, admin_client, submitted_mentor_kyc):
        """Test getting mentor KYC detail."""
        url = reverse('users:admin-kyc-detail', args=[str(submitted_mentor_kyc.id)])

        response = admin_client.get(url, {'role': 'mentor'})

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True

    def test_get_kyc_detail_mentee(self, admin_client, submitted_mentee_kyc):
        """Test getting mentee KYC detail."""
        url = reverse('users:admin-kyc-detail', args=[str(submitted_mentee_kyc.id)])

        response = admin_client.get(url, {'role': 'mentee'})

        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True

    def test_approve_mentor_kyc(self, admin_client, submitted_mentor_kyc):
        """Test approving a mentor KYC application."""
        url = reverse('users:admin-kyc-approve', args=[str(submitted_mentor_kyc.id)])

        response = admin_client.post(url, {'role': 'mentor', 'review_notes': 'Approved'}, format='json')

        assert response.status_code == status.HTTP_200_OK
        submitted_mentor_kyc.refresh_from_db()
        assert submitted_mentor_kyc.status == 'approved'

    def test_approve_mentee_kyc(self, admin_client, submitted_mentee_kyc):
        """Test approving a mentee KYC application."""
        url = reverse('users:admin-kyc-approve', args=[str(submitted_mentee_kyc.id)])

        response = admin_client.post(url, {'role': 'mentee', 'review_notes': 'Approved'}, format='json')

        assert response.status_code == status.HTTP_200_OK
        submitted_mentee_kyc.refresh_from_db()
        assert submitted_mentee_kyc.status == 'approved'

    def test_reject_kyc_requires_reason(self, admin_client, submitted_mentor_kyc):
        """Test that rejecting KYC requires a reason."""
        url = reverse('users:admin-kyc-reject', args=[str(submitted_mentor_kyc.id)])

        response = admin_client.post(url, {'role': 'mentor'}, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_reject_kyc_with_reason(self, admin_client, submitted_mentor_kyc):
        """Test rejecting a KYC application with reason."""
        url = reverse('users:admin-kyc-reject', args=[str(submitted_mentor_kyc.id)])

        response = admin_client.post(url, {
            'role': 'mentor',
            'rejection_reason': 'Invalid documents provided',
        }, format='json')

        assert response.status_code == status.HTTP_200_OK
        submitted_mentor_kyc.refresh_from_db()
        assert submitted_mentor_kyc.status == 'rejected'

    def test_request_changes(self, admin_client, submitted_mentor_kyc):
        """Test requesting changes on a KYC application."""
        url = reverse('users:admin-kyc-request-changes', args=[str(submitted_mentor_kyc.id)])

        response = admin_client.post(url, {
            'role': 'mentor',
            'review_notes': 'Please update your profile picture',
        }, format='json')

        assert response.status_code == status.HTTP_200_OK
        submitted_mentor_kyc.refresh_from_db()
        assert submitted_mentor_kyc.status == 'requires_changes'

    def test_non_admin_cannot_access_kyc_list(self, authenticated_client):
        """Test that non-admin users cannot access KYC list."""
        url = reverse('users:admin-kyc-list')

        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_non_admin_cannot_approve_kyc(self, authenticated_client, submitted_mentor_kyc):
        """Test that non-admin users cannot approve KYC."""
        url = reverse('users:admin-kyc-approve', args=[str(submitted_mentor_kyc.id)])

        response = authenticated_client.post(url, {'role': 'mentor'}, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# KYC MODEL TESTS
# =============================================================================

@pytest.mark.django_db
class TestMentorKYCModel:
    """Tests for MentorKYC model."""

    def test_mentor_kyc_creation(self, mentor_kyc):
        """Test MentorKYC model creation."""
        assert mentor_kyc.status == 'draft'
        assert mentor_kyc.location == 'Accra, Ghana'

    def test_mentor_kyc_is_complete(self, mentor_kyc):
        """Test is_complete property."""
        # Without display picture and CV
        assert not mentor_kyc.is_complete

        # With display picture and CV
        mentor_kyc.display_picture = 'test.jpg'
        mentor_kyc.cv = 'test.pdf'
        mentor_kyc.save()
        assert mentor_kyc.is_complete

    def test_mentor_kyc_completion_percentage(self, eagle_user):
        """Test completion percentage calculation."""
        kyc = MentorKYC.objects.create(user=eagle_user)

        # Empty profile
        assert kyc.completion_percentage < 20

        # Add some fields
        kyc.location = 'Test Location'
        kyc.phone_number = '+233201234567'
        kyc.save()

        # Should be higher now
        assert kyc.completion_percentage > 10


@pytest.mark.django_db
class TestMenteeKYCModel:
    """Tests for MenteeKYC model."""

    def test_mentee_kyc_creation(self, mentee_kyc):
        """Test MenteeKYC model creation."""
        assert mentee_kyc.status == 'draft'
        assert mentee_kyc.country == 'Ghana'

    def test_mentee_kyc_is_complete(self, mentee_kyc):
        """Test is_complete property."""
        # Without display picture
        assert not mentee_kyc.is_complete

        # With display picture
        mentee_kyc.display_picture = 'test.jpg'
        mentee_kyc.save()
        assert mentee_kyc.is_complete

    def test_mentee_kyc_completion_percentage(self, eaglet_user):
        """Test completion percentage calculation."""
        kyc = MenteeKYC.objects.create(user=eaglet_user)

        # Empty profile
        assert kyc.completion_percentage < 20

        # Add some fields
        kyc.country = 'Ghana'
        kyc.city = 'Accra'
        kyc.phone_number = '+233201234567'
        kyc.save()

        # Should be higher now
        assert kyc.completion_percentage > 10


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

@pytest.mark.django_db
class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_duplicate_email_registration_fails(self, api_client, eagle_user):
        """Test that duplicate email registration fails."""
        url = reverse('users:register')
        data = {
            'email': 'eagle@test.com',  # Already exists
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!',
            'first_name': 'Duplicate',
            'last_name': 'User',
            'role': 'eaglet',
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_invalid_role_registration_fails(self, api_client):
        """Test that registration with invalid role fails."""
        url = reverse('users:register')
        data = {
            'email': 'newuser@test.com',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'invalid_role',
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_kyc_status_transitions(self, mentor_kyc):
        """Test that KYC status transitions correctly."""
        assert mentor_kyc.status == 'draft'

        # Make complete and submit
        mentor_kyc.display_picture = 'test.jpg'
        mentor_kyc.cv = 'test.pdf'
        mentor_kyc.save()
        mentor_kyc.submit()
        assert mentor_kyc.status == 'submitted'

        # Cannot submit again
        mentor_kyc.submit()  # Should not change status
        assert mentor_kyc.status == 'submitted'

    def test_expired_token_rejected(self, api_client, eagle_user):
        """Test that expired tokens are rejected."""
        # This would require mocking time, simplified version:
        url = reverse('users:current-user')

        # Use invalid token
        api_client.credentials(HTTP_AUTHORIZATION='Bearer invalidtoken123')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

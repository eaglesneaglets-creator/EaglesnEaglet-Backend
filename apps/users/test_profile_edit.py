"""
Tests for post-approval KYC profile editing (Settings → Profile section).

Policy (two-tier, v1):
  * Approved profiles MAY edit safe fields (contact / preference data).
  * Approved profiles may NOT edit identity fields (national_id_number,
    Code of Conduct snapshot) — those return 400 IdentityFieldLocked.
  * Non-approved profiles keep the existing editing rules.
"""

import pytest

from apps.users.models import MenteeKYC, MentorKYC


@pytest.fixture
def approved_mentor(eagle_user):
    kyc, _ = MentorKYC.objects.get_or_create(user=eagle_user)
    kyc.status = 'approved'
    kyc.national_id_number = 'GHA-000111222'
    kyc.save()
    return eagle_user


@pytest.fixture
def approved_mentee(eaglet_user):
    kyc, _ = MenteeKYC.objects.get_or_create(user=eaglet_user)
    kyc.status = 'approved'
    kyc.national_id_number = 'GHA-333444555'
    kyc.save()
    return eaglet_user


@pytest.mark.django_db
class TestApprovedMentorProfileEdit:
    URL = '/api/v1/auth/mentor-profile/'

    def test_safe_field_edit_allowed_when_approved(self, api_client, approved_mentor):
        api_client.force_authenticate(user=approved_mentor)
        resp = api_client.patch(self.URL, {'location': 'Accra, Ghana'}, format='json')
        assert resp.status_code == 200, resp.content
        assert resp.data['success'] is True
        kyc = MentorKYC.objects.get(user=approved_mentor)
        assert kyc.location == 'Accra, Ghana'
        assert kyc.status == 'approved'  # status untouched by safe edits

    def test_identity_field_locked_when_approved(self, api_client, approved_mentor):
        api_client.force_authenticate(user=approved_mentor)
        resp = api_client.patch(
            self.URL, {'national_id_number': 'GHA-999'}, format='json',
        )
        assert resp.status_code == 400
        assert resp.data['error']['type'] == 'IdentityFieldLocked'
        assert 'national_id_number' in resp.data['error']['details']['locked_fields']
        kyc = MentorKYC.objects.get(user=approved_mentor)
        assert kyc.national_id_number == 'GHA-000111222'  # unchanged

    def test_coc_snapshot_locked_when_approved(self, api_client, approved_mentor):
        api_client.force_authenticate(user=approved_mentor)
        resp = api_client.patch(
            self.URL, {'code_of_conduct_version': 'v9'}, format='json',
        )
        assert resp.status_code == 400
        assert resp.data['error']['type'] == 'IdentityFieldLocked'

    def test_mixed_payload_rejected_entirely(self, api_client, approved_mentor):
        """A payload mixing safe + locked fields must not partially apply."""
        api_client.force_authenticate(user=approved_mentor)
        resp = api_client.patch(
            self.URL,
            {'location': 'Kumasi', 'national_id_number': 'GHA-999'},
            format='json',
        )
        assert resp.status_code == 400
        kyc = MentorKYC.objects.get(user=approved_mentor)
        assert kyc.location != 'Kumasi'

    def test_under_review_still_blocked(self, api_client, eagle_user):
        kyc, _ = MentorKYC.objects.get_or_create(user=eagle_user)
        kyc.status = 'under_review'
        kyc.save()
        api_client.force_authenticate(user=eagle_user)
        resp = api_client.patch(self.URL, {'location': 'Accra'}, format='json')
        assert resp.status_code == 400
        assert resp.data['error']['type'] == 'ApplicationPending'


@pytest.mark.django_db
class TestApprovedMenteeProfileEdit:
    URL = '/api/v1/auth/mentee-profile/'

    def test_safe_field_edit_allowed_when_approved(self, api_client, approved_mentee):
        api_client.force_authenticate(user=approved_mentee)
        resp = api_client.patch(
            self.URL, {'city': 'Accra', 'location': 'Osu'}, format='json',
        )
        assert resp.status_code == 200, resp.content
        kyc = MenteeKYC.objects.get(user=approved_mentee)
        assert kyc.city == 'Accra'
        assert kyc.location == 'Osu'
        assert kyc.status == 'approved'

    def test_identity_field_locked_when_approved(self, api_client, approved_mentee):
        api_client.force_authenticate(user=approved_mentee)
        resp = api_client.patch(
            self.URL, {'national_id_number': 'GHA-999'}, format='json',
        )
        assert resp.status_code == 400
        assert resp.data['error']['type'] == 'IdentityFieldLocked'
        kyc = MenteeKYC.objects.get(user=approved_mentee)
        assert kyc.national_id_number == 'GHA-333444555'

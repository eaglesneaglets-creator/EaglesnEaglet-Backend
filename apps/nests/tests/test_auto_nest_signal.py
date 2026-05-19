"""
Tests for auto-Nest creation on MentorKYC approval (plan 14.5-01 T1).

The signal lives in apps.users.signals and listens to MentorKYC.post_save,
firing only when status transitions TO 'approved' from any other value.
Idempotent via Nest.objects.get_or_create(eagle=...).
"""

import pytest
from django.contrib.auth import get_user_model

from apps.nests.models import Nest
from apps.users.models import MentorKYC

User = get_user_model()


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle.signal@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Auto", last_name="Eagle",
    )


@pytest.mark.django_db(transaction=True)
def test_approval_creates_nest_once(eagle):
    """Transitioning MentorKYC.status -> approved creates exactly one Nest."""
    kyc = MentorKYC.objects.create(user=eagle, status="draft")
    assert Nest.objects.filter(eagle=eagle).count() == 0

    kyc.status = "approved"
    kyc.save()

    nests = Nest.objects.filter(eagle=eagle)
    assert nests.count() == 1, "Expected exactly one Nest after approval"
    nest = nests.first()
    assert nest.name == "Auto's Nest"


@pytest.mark.django_db(transaction=True)
def test_re_save_approved_does_not_duplicate(eagle):
    """Saving an already-approved MentorKYC again does not create a second Nest."""
    kyc = MentorKYC.objects.create(user=eagle, status="approved")
    initial_count = Nest.objects.filter(eagle=eagle).count()
    assert initial_count == 1, "First save should create one Nest"

    # Re-save with same status — must not duplicate.
    kyc.review_notes = "touched"
    kyc.save()

    assert Nest.objects.filter(eagle=eagle).count() == 1


@pytest.mark.django_db(transaction=True)
def test_non_approved_transitions_do_not_create_nest(eagle):
    """Status changes that don't reach 'approved' must not create a Nest."""
    kyc = MentorKYC.objects.create(user=eagle, status="draft")
    kyc.status = "submitted"
    kyc.save()
    kyc.status = "under_review"
    kyc.save()
    kyc.status = "rejected"
    kyc.save()

    assert Nest.objects.filter(eagle=eagle).count() == 0

"""
Mentor profile embedded in nest discovery (Phase 28-01).

The mentee browse card renders person-first mentor data. This suite locks that
NestListSerializer embeds a null-safe `mentor_profile` sourced from MentorKYC,
and that it does not N+1 as the nest count grows.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from apps.nests.models import Nest
from apps.users.models import MentorKYC

User = get_user_model()


@pytest.fixture
def mentee(db):
    return User.objects.create_user(
        email="mentee@test.com", password="p", role=User.Role.EAGLET,
        first_name="Mena", last_name="Tee", is_email_verified=True,
    )


def _make_eagle(email, **kyc_fields):
    eagle = User.objects.create_user(
        email=email, password="p", role=User.Role.EAGLE,
        first_name="Rich", last_name="Densu", is_email_verified=True,
    )
    if kyc_fields:
        MentorKYC.objects.create(user=eagle, **kyc_fields)
    return eagle


@pytest.fixture
def eagle_with_kyc(db):
    return _make_eagle(
        "eagle_kyc@test.com",
        status="approved",
        display_picture="https://cdn.example.com/rich.jpg",
        current_occupation="Financial Analyst",
        area_of_expertise="Finance",
        profile_description="15 years guiding young professionals in stewardship.",
        years_of_service=8,
        location="Accra, Ghana",
        mentorship_types=["Career", "Faith", "Finance", "Extra"],
    )


@pytest.fixture
def public_nest(db, eagle_with_kyc):
    return Nest.objects.create(
        name="Richard's Nest", eagle=eagle_with_kyc,
        privacy=Nest.Privacy.PUBLIC, is_active=True,
    )


@pytest.fixture
def client_as_mentee(mentee):
    c = APIClient()
    c.force_authenticate(mentee)
    return c


def _find(items, nest_id):
    return next(n for n in items if n["id"] == str(nest_id))


@pytest.mark.django_db
def test_discovery_includes_mentor_profile(client_as_mentee, public_nest):
    resp = client_as_mentee.get("/api/v1/nests/")
    assert resp.status_code == 200
    items = resp.json()["data"]  # paginated envelope: {success, data: [...], meta}
    row = _find(items, public_nest.id)
    mp = row["mentor_profile"]
    assert mp is not None
    assert mp["current_occupation"] == "Financial Analyst"
    assert mp["area_of_expertise"] == "Finance"
    assert mp["years_of_service"] == 8
    assert mp["location"] == "Accra, Ghana"
    assert mp["display_picture"] == "https://cdn.example.com/rich.jpg"
    assert "Career" in mp["mentorship_types"]
    assert mp["kyc_verified"] is True


@pytest.mark.django_db
def test_missing_kyc_is_graceful(client_as_mentee, db):
    eagle = _make_eagle("no_kyc@test.com")  # no MentorKYC row
    nest = Nest.objects.create(
        name="Bare Nest", eagle=eagle, privacy=Nest.Privacy.PUBLIC, is_active=True,
    )
    resp = client_as_mentee.get("/api/v1/nests/")
    assert resp.status_code == 200
    row = _find(resp.json()["data"], nest.id)
    assert row["mentor_profile"] is None


@pytest.mark.django_db
def test_unapproved_kyc_not_verified(client_as_mentee, db):
    eagle = _make_eagle(
        "pending@test.com", status="submitted", current_occupation="Teacher",
    )
    nest = Nest.objects.create(
        name="Pending Nest", eagle=eagle, privacy=Nest.Privacy.PUBLIC, is_active=True,
    )
    row = _find(client_as_mentee.get("/api/v1/nests/").json()["data"], nest.id)
    assert row["mentor_profile"]["kyc_verified"] is False
    assert row["mentor_profile"]["current_occupation"] == "Teacher"


@pytest.mark.django_db
def test_no_n_plus_one(client_as_mentee, django_assert_max_num_queries, db):
    """6 nests must not fire a per-nest mentor_profile query (select_related join).

    Without the join, mentor_profile would add ~1 query per nest. A small fixed
    cap that holds for 6 nests proves the join eliminated the N+1.
    """
    for i in range(6):
        e = _make_eagle(
            f"e{i}@test.com", status="approved",
            current_occupation=f"Role {i}", mentorship_types=["X"],
        )
        Nest.objects.create(
            name=f"Nest {i}", eagle=e, privacy=Nest.Privacy.PUBLIC, is_active=True,
        )

    with django_assert_max_num_queries(6):
        resp = client_as_mentee.get("/api/v1/nests/")
    assert resp.status_code == 200
    assert len(resp.json()["data"]) >= 6

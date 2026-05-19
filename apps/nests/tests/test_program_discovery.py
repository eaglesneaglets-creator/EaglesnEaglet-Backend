"""
Tests for plan 14.5-01: program discovery payload, ?nest= filter, single-active
invariant, IsNestMember read-only, and ProgramRulesLocked permission.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from apps.nests.models import Nest, NestMembership
from apps.nests.models_program import (
    Program,
    ProgramObjective,
    ProgramObjectiveRule,
    ProgramEnrollment,
)

User = get_user_model()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle.disc@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="Disc",
    )


@pytest.fixture
def eagle2(db):
    return User.objects.create_user(
        email="eagle.disc2@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="Two",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet.disc@test.com", password="pass",
        role=User.Role.EAGLET, first_name="Eaglet", last_name="Disc",
    )


@pytest.fixture
def nest(eagle):
    return Nest.objects.create(name="Disc Nest", eagle=eagle)


@pytest.fixture
def nest_b(eagle):
    return Nest.objects.create(name="Disc Nest B", eagle=eagle)


@pytest.fixture
def program(nest):
    p = Program.objects.create(nest=nest, name="Growth Program", description="Help mentees grow", status="active")
    obj1 = ProgramObjective.objects.create(program=p, title="Master Modules", description="", order=1)
    ProgramObjectiveRule.objects.create(objective=obj1, rule_type="modules_completed", target=3, config={})
    obj2 = ProgramObjective.objects.create(program=p, title="Engage", description="", order=2)
    ProgramObjectiveRule.objects.create(objective=obj2, rule_type="assignments_passed", target=5, config={})
    ProgramObjectiveRule.objects.create(objective=obj2, rule_type="streak_days", target=7, config={})
    return p


@pytest.fixture
def auth_client():
    def _auth(user):
        c = APIClient()
        c.force_authenticate(user=user)
        return c
    return _auth


# ---------------------------------------------------------------------------
# AC-2: Discovery payload
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_nest_detail_embeds_program(auth_client, eaglet, nest, program):
    client = auth_client(eaglet)
    resp = client.get(f"/api/v1/nests/{nest.id}/")
    assert resp.status_code == 200, resp.content
    data = resp.json()["data"]
    cp = data["current_program"]
    assert cp is not None
    assert cp["name"] == "Growth Program"
    assert len(cp["objectives"]) == 2
    titles = {o["title"] for o in cp["objectives"]}
    assert titles == {"Master Modules", "Engage"}
    summaries = {o["rule_summary"] for o in cp["objectives"]}
    assert "Complete 3 modules" in summaries
    # Multi-rule objective joins with " · "
    multi = next(o for o in cp["objectives"] if o["title"] == "Engage")
    assert " · " in multi["rule_summary"]
    assert "Pass 5 assignments" in multi["rule_summary"]
    assert "Maintain a 7-day streak" in multi["rule_summary"]


@pytest.mark.django_db
def test_nest_detail_current_program_null_when_no_active(auth_client, eaglet, nest):
    client = auth_client(eaglet)
    resp = client.get(f"/api/v1/nests/{nest.id}/")
    assert resp.status_code == 200
    assert resp.json()["data"]["current_program"] is None


# ---------------------------------------------------------------------------
# AC-3: ?nest= filter
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_program_list_filters_by_nest_query(auth_client, eagle, nest, nest_b):
    Program.objects.create(nest=nest, name="Prog A", status="active")
    Program.objects.create(nest=nest_b, name="Prog B", status="active")
    client = auth_client(eagle)

    resp = client.get(f"/api/v1/nests/programs/?nest={nest.id}")
    assert resp.status_code == 200
    names = [p["name"] for p in resp.json().get("data", resp.json().get("results", resp.json()))]
    # Account for either wrapped or DRF default response shape
    body = resp.json()
    items = body.get("data") or body.get("results") or body
    if isinstance(items, dict) and "results" in items:
        items = items["results"]
    names = [p["name"] for p in items]
    assert "Prog A" in names
    assert "Prog B" not in names


# ---------------------------------------------------------------------------
# AC-6: single-active invariant
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_cannot_create_second_active_program(auth_client, eagle, nest):
    Program.objects.create(nest=nest, name="First", status="active")
    client = auth_client(eagle)
    resp = client.post(
        "/api/v1/nests/programs/",
        {"nest": str(nest.id), "name": "Second", "description": "", "status": "active"},
        format="json",
    )
    assert resp.status_code == 400, resp.content
    body = resp.json()
    # ValidationError shape
    assert "ActiveProgramExists" in str(body) or "active program already exists" in str(body).lower()


@pytest.mark.django_db
def test_can_create_draft_alongside_active(auth_client, eagle, nest):
    Program.objects.create(nest=nest, name="Live", status="active")
    client = auth_client(eagle)
    resp = client.post(
        "/api/v1/nests/programs/",
        {"nest": str(nest.id), "name": "Next Draft", "description": "", "status": "draft"},
        format="json",
    )
    assert resp.status_code == 201, resp.content


# ---------------------------------------------------------------------------
# AC-4: IsNestMember allows SAFE_METHODS for INACTIVE
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_inactive_member_can_get_posts(auth_client, eaglet, nest):
    NestMembership.objects.create(nest=nest, user=eaglet, role="member", status="inactive")
    client = auth_client(eaglet)
    resp = client.get(f"/api/v1/nests/{nest.id}/posts/")
    assert resp.status_code == 200, resp.content


@pytest.mark.django_db
def test_inactive_member_cannot_create_post(auth_client, eaglet, nest):
    NestMembership.objects.create(nest=nest, user=eaglet, role="member", status="inactive")
    client = auth_client(eaglet)
    resp = client.post(
        f"/api/v1/nests/{nest.id}/posts/",
        {"content": "should not work"},
        format="json",
    )
    assert resp.status_code == 403, resp.content


# ---------------------------------------------------------------------------
# AC-5: ProgramRulesLocked
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_can_add_objective_before_enrollment(auth_client, eagle, nest):
    p = Program.objects.create(nest=nest, name="Open", status="active")
    client = auth_client(eagle)
    resp = client.post(
        f"/api/v1/nests/programs/{p.id}/objectives/",
        {"title": "Do thing", "description": "", "order": 1},
        format="json",
    )
    assert resp.status_code == 201, resp.content


@pytest.mark.django_db
def test_cannot_add_objective_with_pending_enrollment(auth_client, eagle, eaglet, nest):
    p = Program.objects.create(nest=nest, name="Closed", status="active")
    ProgramEnrollment.objects.create(program=p, mentee=eaglet, status="pending")
    client = auth_client(eagle)
    resp = client.post(
        f"/api/v1/nests/programs/{p.id}/objectives/",
        {"title": "Late add", "description": "", "order": 1},
        format="json",
    )
    assert resp.status_code == 423, resp.content
    assert "ProgramRulesLocked" in str(resp.json())


@pytest.mark.django_db
def test_cannot_delete_rule_with_active_enrollment(auth_client, eagle, eaglet, nest):
    p = Program.objects.create(nest=nest, name="Closed Active", status="active")
    obj = ProgramObjective.objects.create(program=p, title="Goal", description="", order=1)
    rule = ProgramObjectiveRule.objects.create(objective=obj, rule_type="points_earned", target=100, config={})
    ProgramEnrollment.objects.create(program=p, mentee=eaglet, status="active")
    client = auth_client(eagle)
    resp = client.delete(
        f"/api/v1/nests/programs/{p.id}/objectives/{obj.id}/rules/{rule.id}/"
    )
    assert resp.status_code == 423, resp.content

"""
Tests for Program domain models + admin endpoints (plan 14-01).

Coverage:
- Model defaults + happy path
- Status transition rules (clean())
- Partial unique index for active-program-per-nest (Postgres only — SQLite
  test runner skips since it ignores the WHERE clause)
- ProgramObjectiveRule validation
- Admin endpoint authorization (eagle owns / eagle non-owner / eaglet / staff)
- activated_at / archived_at timestamp side-effects on status flips
"""

import uuid

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.nests.models import Nest
from apps.nests.models_program import (
    Program,
    ProgramObjective,
    ProgramObjectiveRule,
)

User = get_user_model()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="One",
    )


@pytest.fixture
def other_eagle(db):
    return User.objects.create_user(
        email="eagle2@test.com", password="pass",
        role=User.Role.EAGLE, first_name="Eagle", last_name="Two",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com", password="pass",
        role=User.Role.EAGLET, first_name="Eaglet", last_name="One",
    )


@pytest.fixture
def staff(db):
    return User.objects.create_user(
        email="staff@test.com", password="pass",
        role=User.Role.ADMIN, first_name="Staff", last_name="User",
        is_staff=True,
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="Eagle One Nest", eagle=eagle)


@pytest.fixture
def other_nest(db, other_eagle):
    return Nest.objects.create(name="Eagle Two Nest", eagle=other_eagle)


@pytest.fixture
def program(db, nest, eagle):
    return Program.objects.create(
        nest=nest, name="Default Program", created_by=eagle,
    )


@pytest.fixture
def auth_client():
    """Returns a callable that produces an authenticated APIClient."""

    def _auth(user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    return _auth


# ---------------------------------------------------------------------------
# Model: Program
# ---------------------------------------------------------------------------


class TestProgramModel:
    def test_create_with_minimal_fields_defaults_to_draft(self, nest):
        p = Program.objects.create(nest=nest, name="Test")
        assert p.status == Program.Status.DRAFT
        assert p.activated_at is None
        assert p.archived_at is None

    def test_two_active_programs_in_different_nests_allowed(self, nest, other_nest):
        Program.objects.create(nest=nest, name="A", status=Program.Status.ACTIVE)
        Program.objects.create(nest=other_nest, name="B", status=Program.Status.ACTIVE)
        assert Program.objects.filter(status=Program.Status.ACTIVE).count() == 2

    @pytest.mark.skipif(
        connection.vendor != "postgresql",
        reason="Partial unique index is Postgres-only; SQLite ignores WHERE clause.",
    )
    def test_only_one_active_program_per_nest(self, nest):
        Program.objects.create(nest=nest, name="A", status=Program.Status.ACTIVE)
        with pytest.raises(IntegrityError):
            with transaction.atomic():
                Program.objects.create(nest=nest, name="B", status=Program.Status.ACTIVE)

    def test_status_transition_draft_to_active_allowed(self, program):
        program.status = Program.Status.ACTIVE
        program.full_clean()  # no raise

    def test_status_transition_active_to_archived_allowed(self, program):
        program.status = Program.Status.ACTIVE
        program.save()
        program.status = Program.Status.ARCHIVED
        program.full_clean()  # no raise

    def test_status_transition_archived_to_active_rejected(self, program):
        program.status = Program.Status.ARCHIVED
        program.save()
        program.status = Program.Status.ACTIVE
        with pytest.raises(ValidationError) as exc:
            program.full_clean()
        assert "status" in exc.value.message_dict

    def test_status_transition_active_to_draft_rejected(self, program):
        program.status = Program.Status.ACTIVE
        program.save()
        program.status = Program.Status.DRAFT
        with pytest.raises(ValidationError):
            program.full_clean()


# ---------------------------------------------------------------------------
# Model: ProgramObjectiveRule
# ---------------------------------------------------------------------------


class TestProgramObjectiveRule:
    def test_target_must_be_positive(self, program):
        objective = ProgramObjective.objects.create(program=program, title="Obj")
        rule = ProgramObjectiveRule(
            objective=objective,
            rule_type=ProgramObjectiveRule.RuleType.MODULES_COMPLETED,
            target=0,
        )
        with pytest.raises(ValidationError) as exc:
            rule.full_clean()
        assert "target" in exc.value.message_dict

    def test_config_must_be_dict(self, program):
        objective = ProgramObjective.objects.create(program=program, title="Obj")
        rule = ProgramObjectiveRule(
            objective=objective,
            rule_type=ProgramObjectiveRule.RuleType.POINTS_EARNED,
            target=100,
            config=[],  # invalid — list, not dict
        )
        with pytest.raises(ValidationError) as exc:
            rule.full_clean()
        assert "config" in exc.value.message_dict

    def test_valid_rule_passes_clean(self, program):
        objective = ProgramObjective.objects.create(program=program, title="Obj")
        rule = ProgramObjectiveRule(
            objective=objective,
            rule_type=ProgramObjectiveRule.RuleType.STREAK_DAYS,
            target=7,
            config={"min_activity_per_day": 1},
        )
        rule.full_clean()  # no raise


# ---------------------------------------------------------------------------
# Endpoints: /api/v1/nests/programs/
# ---------------------------------------------------------------------------


class TestProgramAdminEndpoints:
    def test_eagle_can_create_program_for_own_nest(self, auth_client, eagle, nest):
        client = auth_client(eagle)
        resp = client.post(
            "/api/v1/nests/programs/",
            {"nest": str(nest.id), "name": "My Program"},
            format="json",
        )
        assert resp.status_code == status.HTTP_201_CREATED, resp.data
        assert Program.objects.filter(nest=nest, name="My Program").exists()

    def test_eagle_cannot_create_program_for_other_nest(self, auth_client, eagle, other_nest):
        client = auth_client(eagle)
        resp = client.post(
            "/api/v1/nests/programs/",
            {"nest": str(other_nest.id), "name": "Hijack"},
            format="json",
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN, resp.data

    def test_staff_can_create_program_for_any_nest(self, auth_client, staff, other_nest):
        client = auth_client(staff)
        resp = client.post(
            "/api/v1/nests/programs/",
            {"nest": str(other_nest.id), "name": "Staff Program"},
            format="json",
        )
        assert resp.status_code == status.HTTP_201_CREATED, resp.data

    def test_eaglet_forbidden(self, auth_client, eaglet, nest):
        client = auth_client(eaglet)
        resp = client.post(
            "/api/v1/nests/programs/",
            {"nest": str(nest.id), "name": "Mentee Hijack"},
            format="json",
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    def test_unauthenticated_forbidden(self, db, nest):
        client = APIClient()
        resp = client.post(
            "/api/v1/nests/programs/",
            {"nest": str(nest.id), "name": "Anon"},
            format="json",
        )
        assert resp.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    def test_eagle_list_is_scoped_to_own_nests(self, auth_client, eagle, nest, other_nest):
        Program.objects.create(nest=nest, name="Mine")
        Program.objects.create(nest=other_nest, name="Theirs")
        client = auth_client(eagle)
        resp = client.get("/api/v1/nests/programs/")
        assert resp.status_code == status.HTTP_200_OK

        # Response may be a paginated dict ({"results": [...]}) or a plain
        # list depending on whether DRF pagination is enabled globally.
        data = resp.data
        if isinstance(data, dict) and "results" in data:
            items = data["results"]
        elif isinstance(data, dict) and "data" in data:
            items = data["data"]
        else:
            items = data
        names = {p["name"] for p in items}
        assert names == {"Mine"}

    def test_activated_at_set_when_status_flips_to_active(self, auth_client, eagle, program):
        client = auth_client(eagle)
        resp = client.patch(
            f"/api/v1/nests/programs/{program.id}/",
            {"status": "active"},
            format="json",
        )
        assert resp.status_code == status.HTTP_200_OK, resp.data
        program.refresh_from_db()
        assert program.activated_at is not None

    def test_archived_at_set_when_status_flips_to_archived(self, auth_client, eagle, program):
        program.status = Program.Status.ACTIVE
        program.save()
        client = auth_client(eagle)
        resp = client.patch(
            f"/api/v1/nests/programs/{program.id}/",
            {"status": "archived"},
            format="json",
        )
        assert resp.status_code == status.HTTP_200_OK, resp.data
        program.refresh_from_db()
        assert program.archived_at is not None

    def test_archived_program_cannot_be_reactivated(self, auth_client, eagle, program):
        program.status = Program.Status.ARCHIVED
        program.save()
        client = auth_client(eagle)
        resp = client.patch(
            f"/api/v1/nests/programs/{program.id}/",
            {"status": "active"},
            format="json",
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST


# ---------------------------------------------------------------------------
# Endpoints: nested objective + rule routes
# ---------------------------------------------------------------------------


class TestObjectiveAndRuleEndpoints:
    def test_eagle_can_add_objective_to_own_program(self, auth_client, eagle, program):
        client = auth_client(eagle)
        resp = client.post(
            f"/api/v1/nests/programs/{program.id}/objectives/",
            {"title": "Finish 5 modules", "order": 1},
            format="json",
        )
        assert resp.status_code == status.HTTP_201_CREATED, resp.data
        assert ProgramObjective.objects.filter(program=program).count() == 1

    def test_eagle_cannot_add_objective_to_foreign_program(
        self, auth_client, eagle, other_nest
    ):
        foreign = Program.objects.create(nest=other_nest, name="Foreign")
        client = auth_client(eagle)
        resp = client.post(
            f"/api/v1/nests/programs/{foreign.id}/objectives/",
            {"title": "Hijack", "order": 1},
            format="json",
        )
        assert resp.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND)

    def test_eagle_can_add_rule_to_own_objective(self, auth_client, eagle, program):
        objective = ProgramObjective.objects.create(program=program, title="Obj", order=1)
        client = auth_client(eagle)
        resp = client.post(
            f"/api/v1/nests/programs/{program.id}/objectives/{objective.id}/rules/",
            {"rule_type": "modules_completed", "target": 5, "config": {}},
            format="json",
        )
        assert resp.status_code == status.HTTP_201_CREATED, resp.data
        assert ProgramObjectiveRule.objects.filter(objective=objective).count() == 1

    def test_rule_target_zero_rejected_at_api(self, auth_client, eagle, program):
        objective = ProgramObjective.objects.create(program=program, title="Obj", order=1)
        client = auth_client(eagle)
        resp = client.post(
            f"/api/v1/nests/programs/{program.id}/objectives/{objective.id}/rules/",
            {"rule_type": "points_earned", "target": 0, "config": {}},
            format="json",
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST


# ---------------------------------------------------------------------------
# Sanity: unrelated nest endpoints still resolve (regression guard)
# ---------------------------------------------------------------------------


class TestUrlRegressionGuard:
    def test_nest_list_route_still_resolves(self, auth_client, eagle):
        """Ensure adding /programs/ before the nest router didn't break /nests/."""
        client = auth_client(eagle)
        resp = client.get("/api/v1/nests/")
        # Just need a 2xx — content shape covered elsewhere.
        assert 200 <= resp.status_code < 300, resp.status_code

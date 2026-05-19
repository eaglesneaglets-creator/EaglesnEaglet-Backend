"""Tests for `python manage.py backfill_programs` (plan 14-03)."""

from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command

from apps.nests.models import MentorshipRequest, Nest, NestMembership
from apps.nests.models_program import Program, ProgramEnrollment

User = get_user_model()


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="bf_eagle@test.com", password="p", role=User.Role.EAGLE,
    )


@pytest.fixture
def eagle2(db):
    return User.objects.create_user(
        email="bf_eagle2@test.com", password="p", role=User.Role.EAGLE,
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="bf_eaglet@test.com", password="p", role=User.Role.EAGLET,
    )


@pytest.fixture
def eaglet2(db):
    return User.objects.create_user(
        email="bf_eaglet2@test.com", password="p", role=User.Role.EAGLET,
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="BF Nest", eagle=eagle)


@pytest.fixture
def nest2(db, eagle2):
    return Nest.objects.create(name="BF Nest 2", eagle=eagle2)


def _run(*args):
    out = StringIO()
    call_command("backfill_programs", *args, stdout=out)
    return out.getvalue()


class TestBackfillCommand:
    def test_dry_run_makes_no_writes(self, db, nest):
        out = _run("--dry-run")
        assert "DRY-RUN" in out
        assert Program.objects.count() == 0

    def test_creates_default_program_for_nest(self, db, nest):
        _run()
        assert Program.objects.filter(nest=nest, status="active").count() == 1

    def test_skips_nest_with_existing_active_program(self, db, nest):
        Program.objects.create(nest=nest, name="Custom", status=Program.Status.ACTIVE)
        _run()
        assert Program.objects.filter(nest=nest, status="active").count() == 1

    def test_active_membership_becomes_active_enrollment(self, db, nest, eaglet):
        # Membership signal would normally NOT fire because no enrollment exists yet.
        NestMembership.objects.create(nest=nest, user=eaglet)
        _run()
        e = ProgramEnrollment.objects.get(mentee=eaglet)
        assert e.status == ProgramEnrollment.Status.ACTIVE
        assert e.program.nest == nest

    def test_pending_request_becomes_pending_enrollment(self, db, nest, eaglet):
        MentorshipRequest.objects.create(
            nest=nest, eaglet=eaglet, message="hi",
        )
        _run()
        e = ProgramEnrollment.objects.get(mentee=eaglet)
        assert e.status == ProgramEnrollment.Status.PENDING
        assert e.application_message == "hi"

    def test_idempotent_second_run(self, db, nest, eaglet):
        NestMembership.objects.create(nest=nest, user=eaglet)
        _run()
        before = ProgramEnrollment.objects.count()
        _run()
        assert ProgramEnrollment.objects.count() == before

    def test_nest_id_scoping(self, db, nest, nest2, eaglet, eaglet2):
        NestMembership.objects.create(nest=nest, user=eaglet)
        NestMembership.objects.create(nest=nest2, user=eaglet2)
        _run("--nest-id", str(nest.id))
        assert Program.objects.filter(nest=nest, status="active").exists()
        assert not Program.objects.filter(nest=nest2, status="active").exists()
        assert ProgramEnrollment.objects.filter(mentee=eaglet).exists()
        assert not ProgramEnrollment.objects.filter(mentee=eaglet2).exists()

    def test_active_membership_takes_priority_over_pending_request(
        self, db, nest, nest2, eaglet,
    ):
        NestMembership.objects.create(nest=nest, user=eaglet)
        MentorshipRequest.objects.create(nest=nest2, eaglet=eaglet, message="x")
        _run()
        # mentee gets the ACTIVE enrollment from the membership; pending blocked
        assert ProgramEnrollment.objects.filter(
            mentee=eaglet, status=ProgramEnrollment.Status.ACTIVE,
        ).count() == 1
        assert not ProgramEnrollment.objects.filter(
            mentee=eaglet, status=ProgramEnrollment.Status.PENDING,
        ).exists()

    def test_skips_already_enrolled_mentee(self, db, nest, eaglet):
        prog = Program.objects.create(nest=nest, name="P", status=Program.Status.ACTIVE)
        ProgramEnrollment.objects.create(
            program=prog, mentee=eaglet, status=ProgramEnrollment.Status.ACTIVE,
        )
        # NestMembership auto-created by enrollment signal — no manual insert needed.
        _run()
        assert ProgramEnrollment.objects.filter(mentee=eaglet).count() == 1

    def test_chunk_size_honored(self, db, nest):
        # Just ensure no crash with chunk-size override
        _run("--chunk-size", "1")
        assert Program.objects.filter(nest=nest).exists()

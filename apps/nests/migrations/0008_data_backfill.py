"""
Data migration (plan 14-03): backfill default Programs + ProgramEnrollments.

Forward: idempotent backfill of three things:
  1. Default Program per Nest lacking an active one
  2. ACTIVE ProgramEnrollment for each active eaglet NestMembership
  3. PENDING ProgramEnrollment for each pending eaglet MentorshipRequest

Reverse: NO-OP (logged). Backfilled rows stay even on rollback because the
downstream FE expects them to exist. To fully unwind, manually delete after
reverting code.
"""

import logging

from django.db import migrations

logger = logging.getLogger(__name__)


def _backfill(apps, schema_editor):
    Nest = apps.get_model("nests", "Nest")
    NestMembership = apps.get_model("nests", "NestMembership")
    MentorshipRequest = apps.get_model("nests", "MentorshipRequest")
    Program = apps.get_model("nests", "Program")
    ProgramEnrollment = apps.get_model("nests", "ProgramEnrollment")

    programs_created = 0
    for nest in Nest.objects.all():
        if Program.objects.filter(nest=nest, status="active").exists():
            continue
        Program.objects.create(
            nest=nest,
            name="Default Program",
            description="Auto-created during program migration.",
            status="active",
        )
        programs_created += 1

    active_created = 0
    memberships = NestMembership.objects.filter(
        status="active", user__role="eaglet",
    ).select_related("nest", "user").order_by("created_at")
    for m in memberships:
        if ProgramEnrollment.objects.filter(
            mentee=m.user, status="active",
        ).exists():
            continue
        program = Program.objects.filter(nest=m.nest, status="active").first()
        if program is None:
            continue
        ProgramEnrollment.objects.create(
            program=program,
            mentee=m.user,
            status="active",
            started_at=m.created_at,
            rules_snapshot={},
        )
        active_created += 1

    pending_created = 0
    requests = MentorshipRequest.objects.filter(
        status="pending", eaglet__role="eaglet",
    ).select_related("nest", "eaglet").order_by("created_at")
    for r in requests:
        if ProgramEnrollment.objects.filter(
            mentee=r.eaglet, status="pending",
        ).exists():
            continue
        if ProgramEnrollment.objects.filter(
            mentee=r.eaglet, status="active",
        ).exists():
            continue
        program = Program.objects.filter(nest=r.nest, status="active").first()
        if program is None:
            continue
        ProgramEnrollment.objects.create(
            program=program,
            mentee=r.eaglet,
            status="pending",
            application_message=r.message or "",
        )
        pending_created += 1

    logger.info(
        "Program backfill: programs=%s active=%s pending=%s",
        programs_created, active_created, pending_created,
    )


def _reverse_noop(apps, schema_editor):
    logger.warning(
        "Program backfill reverse is a no-op. "
        "Delete Program / ProgramEnrollment rows manually if needed."
    )


class Migration(migrations.Migration):

    dependencies = [
        ("nests", "0007_programenrollment_programexitrequest_and_more"),
    ]

    operations = [
        migrations.RunPython(_backfill, _reverse_noop),
    ]

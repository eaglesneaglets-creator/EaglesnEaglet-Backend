"""
Backfill existing live data into the new Program domain (plan 14-03).

Operations (idempotent):
  1. Each Nest without an active Program → create "Default Program".
  2. Each active eaglet NestMembership without a matching ACTIVE
     ProgramEnrollment → create one (started_at = membership.created_at).
  3. Each pending MentorshipRequest from an eaglet without a matching
     PENDING ProgramEnrollment → create a PENDING enrollment.

Usage:
    python manage.py backfill_programs [--dry-run] [--chunk-size N] [--nest-id UUID]
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from apps.nests.models import MentorshipRequest, Nest, NestMembership
from apps.nests.models_program import Program, ProgramEnrollment


class Command(BaseCommand):
    help = "Backfill Programs + ProgramEnrollments from existing memberships/requests."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Compute counts only; do not write.",
        )
        parser.add_argument(
            "--chunk-size", type=int, default=200,
            help="Rows per transaction (default: 200).",
        )
        parser.add_argument(
            "--nest-id", type=str, default=None,
            help="Limit backfill to a single Nest by UUID.",
        )

    def handle(self, *args, **opts):
        dry_run = opts["dry_run"]
        chunk_size = opts["chunk_size"]
        nest_id = opts.get("nest_id")

        prefix = "[DRY-RUN] " if dry_run else ""
        self.stdout.write(self.style.NOTICE(f"{prefix}Backfill starting (chunk={chunk_size})"))

        nests = Nest.objects.all()
        if nest_id:
            nests = nests.filter(pk=nest_id)

        programs_created = self._backfill_default_programs(nests, dry_run, chunk_size)
        active_created = self._backfill_active_enrollments(nests, dry_run, chunk_size)
        pending_created = self._backfill_pending_enrollments(nests, dry_run, chunk_size)

        self.stdout.write(self.style.SUCCESS(
            f"{prefix}Done. programs={programs_created} "
            f"active_enrollments={active_created} pending_enrollments={pending_created}"
        ))

    # ------------------------------------------------------------------

    def _backfill_default_programs(self, nests, dry_run, chunk_size):
        created = 0
        nests_needing_program = nests.exclude(
            programs__status=Program.Status.ACTIVE,
        ).distinct()

        ids = list(nests_needing_program.values_list("id", flat=True))
        for i in range(0, len(ids), chunk_size):
            chunk = ids[i:i + chunk_size]
            if dry_run:
                created += len(chunk)
                continue
            with transaction.atomic():
                for nest_pk in chunk:
                    _, was_created = Program.objects.get_or_create(
                        nest_id=nest_pk,
                        status=Program.Status.ACTIVE,
                        defaults={
                            "name": "Default Program",
                            "description": "Auto-created during program migration.",
                        },
                    )
                    if was_created:
                        created += 1
        return created

    def _backfill_active_enrollments(self, nests, dry_run, chunk_size):
        created = 0
        nest_ids = list(nests.values_list("id", flat=True))

        memberships = NestMembership.objects.filter(
            nest_id__in=nest_ids,
            status=NestMembership.Status.ACTIVE,
            user__role="eaglet",
        ).select_related("nest", "user").order_by("created_at")

        ids = list(memberships.values_list("id", flat=True))
        for i in range(0, len(ids), chunk_size):
            chunk_ids = ids[i:i + chunk_size]
            chunk = NestMembership.objects.filter(id__in=chunk_ids).select_related("nest", "user")
            if dry_run:
                for m in chunk:
                    if not self._has_active_enrollment(m.user_id):
                        created += 1
                continue
            with transaction.atomic():
                for m in chunk:
                    if self._has_active_enrollment(m.user_id):
                        continue
                    program = Program.objects.filter(
                        nest=m.nest, status=Program.Status.ACTIVE,
                    ).first()
                    if program is None:
                        continue
                    ProgramEnrollment.objects.create(
                        program=program,
                        mentee=m.user,
                        status=ProgramEnrollment.Status.ACTIVE,
                        started_at=m.created_at,
                        rules_snapshot={},
                    )
                    created += 1
        return created

    def _backfill_pending_enrollments(self, nests, dry_run, chunk_size):
        created = 0
        nest_ids = list(nests.values_list("id", flat=True))
        requests = MentorshipRequest.objects.filter(
            nest_id__in=nest_ids,
            status=MentorshipRequest.Status.PENDING,
            eaglet__role="eaglet",
        ).select_related("nest", "eaglet").order_by("created_at")

        ids = list(requests.values_list("id", flat=True))
        for i in range(0, len(ids), chunk_size):
            chunk_ids = ids[i:i + chunk_size]
            chunk = MentorshipRequest.objects.filter(id__in=chunk_ids).select_related("nest", "eaglet")
            if dry_run:
                for r in chunk:
                    if (
                        not self._has_pending_enrollment(r.eaglet_id)
                        and not self._has_active_enrollment(r.eaglet_id)
                    ):
                        created += 1
                continue
            with transaction.atomic():
                for r in chunk:
                    if self._has_pending_enrollment(r.eaglet_id):
                        continue
                    if self._has_active_enrollment(r.eaglet_id):
                        continue
                    program = Program.objects.filter(
                        nest=r.nest, status=Program.Status.ACTIVE,
                    ).first()
                    if program is None:
                        continue
                    ProgramEnrollment.objects.create(
                        program=program,
                        mentee=r.eaglet,
                        status=ProgramEnrollment.Status.PENDING,
                        application_message=r.message or "",
                    )
                    created += 1
        return created

    @staticmethod
    def _has_active_enrollment(user_id) -> bool:
        return ProgramEnrollment.objects.filter(
            mentee_id=user_id, status=ProgramEnrollment.Status.ACTIVE,
        ).exists()

    @staticmethod
    def _has_pending_enrollment(user_id) -> bool:
        return ProgramEnrollment.objects.filter(
            mentee_id=user_id, status=ProgramEnrollment.Status.PENDING,
        ).exists()

"""
Backfill NestActivity from pre-existing data (Phase 27 follow-up).

The NestActivity audit log only records events that happen AFTER its signals
shipped (Phase 27-01). Nests active before then show an empty Activity tab even
though they have real posts, shared resources, and members. This one-time command
reconstructs the missing history from existing rows, dated to each record's real
`created_at`/`joined_at`.

Idempotent: every synthesized row carries `metadata.source_ref` (e.g. "post:<id>")
and the command skips any source already backfilled, so re-running is safe.

Usage:
    python manage.py backfill_nest_activity            # all nests
    python manage.py backfill_nest_activity --nest <id> # one nest
    python manage.py backfill_nest_activity --dry-run   # report only, no writes
"""

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction

from apps.nests.models import Nest, NestMembership
from apps.nests.models_activity import NestActivity

# Signal-created rows get their own auto_now_add timestamp a few ms after the
# source row, so exact-time dedup misses them. Match within this window instead.
_DEDUP_WINDOW = timedelta(seconds=2)


def _name(user):
    return getattr(user, "full_name", None) or (str(user) if user else "Unknown")


class Command(BaseCommand):
    help = "Reconstruct NestActivity rows from existing posts, resources, and memberships."

    def add_arguments(self, parser):
        parser.add_argument("--nest", dest="nest_id", default=None,
                            help="Backfill a single nest by id (default: all nests).")
        parser.add_argument("--dry-run", action="store_true",
                            help="Report what would be created without writing.")

    def handle(self, *args, **options):
        nest_id = options["nest_id"]
        dry_run = options["dry_run"]

        nests = Nest.all_objects.all()
        if nest_id:
            nests = nests.filter(pk=nest_id)
            if not nests.exists():
                self.stderr.write(self.style.ERROR(f"Nest {nest_id} not found."))
                return

        # Which sources are already backfilled? One query, not per-row.
        existing_refs = set(
            NestActivity.objects
            .exclude(metadata__source_ref__isnull=True)
            .values_list("metadata__source_ref", flat=True)
        )

        def _already_logged(nest, actor_id, action_type, when):
            """True if a signal-created activity already covers this source.

            Signal rows (created after 27-01 shipped) carry NO source_ref, so
            source_ref dedup alone would DOUBLE-log a post/resource/join that a
            signal already recorded. The signal fires a few ms after the source
            row (each gets its own auto_now_add), so match on (nest, actor,
            action) within a small time window rather than an exact timestamp.
            """
            return NestActivity.objects.filter(
                nest=nest, actor_id=actor_id, action_type=action_type,
                created_at__gte=when - _DEDUP_WINDOW,
                created_at__lte=when + _DEDUP_WINDOW,
            ).exists()

        # (action_type, actor, target, when, source_ref) tuples to create.
        planned = []

        for nest in nests:
            for m in nest.memberships.filter(status=NestMembership.Status.ACTIVE).select_related("user"):
                ref = f"membership:{m.id}"
                actor_id = m.user_id
                if ref in existing_refs or _already_logged(
                    nest, actor_id, NestActivity.ActionType.MEMBER_JOINED, m.joined_at,
                ):
                    continue
                planned.append((
                    nest, m.user, NestActivity.ActionType.MEMBER_JOINED,
                    _name(m.user), m.joined_at, ref,
                ))

            for r in nest.resources.select_related("uploaded_by"):
                ref = f"resource:{r.id}"
                if ref in existing_refs or _already_logged(
                    nest, r.uploaded_by_id, NestActivity.ActionType.CONTENT_SHARED, r.created_at,
                ):
                    continue
                planned.append((
                    nest, r.uploaded_by, NestActivity.ActionType.CONTENT_SHARED,
                    r.title, r.created_at, ref,
                ))

            for p in nest.posts.select_related("author"):
                ref = f"post:{p.id}"
                if ref in existing_refs or _already_logged(
                    nest, p.author_id, NestActivity.ActionType.POST_CREATED, p.created_at,
                ):
                    continue
                planned.append((
                    nest, p.author, NestActivity.ActionType.POST_CREATED,
                    (p.content or "")[:80], p.created_at, ref,
                ))

        if dry_run:
            self.stdout.write(f"[dry-run] Would create {len(planned)} NestActivity rows.")
            for nest, actor, action, target, when, ref in planned[:20]:
                self.stdout.write(f"  {when:%Y-%m-%d} {action} · {target[:40]} ({ref})")
            if len(planned) > 20:
                self.stdout.write(f"  … and {len(planned) - 20} more")
            return

        created = 0
        with transaction.atomic():
            for nest, actor, action, target, when, ref in planned:
                # created_at is auto_now_add, so set the real historical date
                # via an explicit update after insert.
                row = NestActivity.objects.create(
                    nest=nest, actor=actor, action_type=action,
                    target=target or "", metadata={"source_ref": ref, "backfilled": True},
                )
                NestActivity.objects.filter(pk=row.pk).update(created_at=when)
                created += 1

        self.stdout.write(self.style.SUCCESS(
            f"Backfilled {created} NestActivity rows "
            f"({len(existing_refs)} sources already present, skipped)."
        ))

"""
Audit historical manual point awards against the current PointsPolicy (Phase 31-01).

REPORT ONLY — this command never writes. `PointTransaction` is an append-only
ledger ("Never update or delete"), so any correction must be a *compensating
negative transaction*, never an edit to an existing row. Deciding on corrections
is left to a human; this command only surfaces what exceeded policy.

Useful before tightening the policy: see how much historical activity the new
limits would have blocked.

Usage:
    python manage.py audit_manual_awards
    python manage.py audit_manual_awards --since 2026-01-01
    python manage.py audit_manual_awards --limit 100
"""

from collections import defaultdict
from datetime import datetime

from django.core.management.base import BaseCommand
from django.db.models import Sum

from apps.points.models import PointsPolicy, PointTransaction


class Command(BaseCommand):
    help = "Report manual point awards that exceed the current PointsPolicy. Read-only."

    def add_arguments(self, parser):
        parser.add_argument(
            "--since", dest="since", default=None,
            help="Only audit awards on/after this date (YYYY-MM-DD).",
        )
        parser.add_argument(
            "--limit", dest="limit", type=int, default=50,
            help="Max offending rows to print per section (default 50).",
        )

    def handle(self, *args, **options):
        policy = PointsPolicy.load()
        limit = options["limit"]

        qs = PointTransaction.objects.filter(
            source=PointTransaction.Source.MANUAL
        ).select_related("awarded_by", "user")

        if options["since"]:
            try:
                since = datetime.strptime(options["since"], "%Y-%m-%d").date()
            except ValueError:
                self.stderr.write(self.style.ERROR("--since must be YYYY-MM-DD"))
                return
            qs = qs.filter(created_at__date__gte=since)

        total_manual = qs.count()
        self.stdout.write(f"Policy: max {policy.max_manual_award}/award, "
                          f"{policy.daily_points_per_mentor}/mentor/day "
                          f"({'enforced' if policy.is_enforced else 'NOT enforced'})")
        self.stdout.write(f"Manual awards in scope: {total_manual}\n")

        # --- 1. Awards over the per-award ceiling ---------------------------
        over_ceiling = qs.filter(points__gt=policy.max_manual_award).order_by("-points")
        count_over = over_ceiling.count()

        self.stdout.write(self.style.MIGRATE_HEADING(
            f"[1] Awards above the {policy.max_manual_award}-point ceiling: {count_over}"
        ))
        for txn in over_ceiling[:limit]:
            awarder = getattr(txn.awarded_by, "email", "(deleted user)")
            self.stdout.write(
                f"    {txn.created_at:%Y-%m-%d}  {txn.points:>6} pts  "
                f"by {awarder} → {getattr(txn.user, 'email', '?')}"
            )
        if count_over > limit:
            self.stdout.write(f"    … and {count_over - limit} more")

        # --- 2. Awarder/day totals over the daily budget --------------------
        daily = defaultdict(int)
        for row in qs.values("awarded_by__email", "created_at__date").annotate(
            total=Sum("points")
        ):
            if row["total"] and row["total"] > policy.daily_points_per_mentor:
                key = (row["awarded_by__email"] or "(deleted user)",
                       row["created_at__date"])
                daily[key] = row["total"]

        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING(
            f"[2] Mentor-days above the {policy.daily_points_per_mentor}-point "
            f"daily budget: {len(daily)}"
        ))
        for (email, day), total in sorted(daily.items(), key=lambda kv: -kv[1])[:limit]:
            self.stdout.write(f"    {day}  {total:>6} pts  by {email}")
        if len(daily) > limit:
            self.stdout.write(f"    … and {len(daily) - limit} more")

        self.stdout.write("")
        if count_over or daily:
            self.stdout.write(self.style.WARNING(
                "Report only — no rows were modified. The ledger is append-only; "
                "corrections must be compensating negative transactions."
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                "No manual awards exceed the current policy."
            ))

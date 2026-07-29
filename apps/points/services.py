"""
Points Services

Business logic for the gamification system: auto/manual point awards,
leaderboard calculations, badge checking, and streak tracking.
"""

import logging
from datetime import timedelta

from django.core.cache import cache
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied, ValidationError

from apps.users.models import User
from .models import PointConfiguration, PointsPolicy, PointTransaction, Badge, UserBadge

logger = logging.getLogger(__name__)


class PointService:
    """Handles all point-related business logic."""

    # ------------------------------------------------------------------
    # Auto Award
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def award_points(
        user,
        activity_type: str,
        source_id=None,
        nest=None,
        description: str = "",
        override_points: int = None,
    ) -> PointTransaction | None:
        """
        Automatically award points based on activity type and configuration.

        Returns None if the activity type is disabled or doesn't exist.
        Prevents duplicate awards for the same source_id + activity_type.
        """
        # Acquire SELECT FOR UPDATE lock on the User row to serialize
        # concurrent point awards (mitigates Race Condition bug #1 —
        # Duplicate Point Transactions). The fetched row is intentionally
        # discarded — the side effect (row lock) is the whole point.
        try:
            User.objects.select_for_update().filter(pk=user.id).first()
        except User.DoesNotExist:
            pass

        try:
            config = PointConfiguration.objects.get(
                activity_type=activity_type, is_active=True
            )
        except PointConfiguration.DoesNotExist:
            # Fallback: create a default configuration if missing
            # This prevents 500 errors when new features are deployed without seeding
            logger.warning("No active config for activity: %s. Creating default.", activity_type)
            config = PointConfiguration.objects.create(
                activity_type=activity_type,
                points_value=10,  # Default fallback points
                is_active=True,
                description=f"Automated config for {activity_type.replace('_', ' ')}"
            )

        # Prevent duplicate awarding for the same source
        if source_id and PointTransaction.objects.filter(
            user=user, activity_type=activity_type, source_id=source_id
        ).exists():
            logger.debug("Duplicate award prevented: %s / %s", activity_type, source_id)
            return None

        points_to_award = override_points if override_points is not None and override_points > 0 else config.points_value

        txn = PointTransaction.objects.create(
            user=user,
            points=points_to_award,
            activity_type=activity_type,
            source=PointTransaction.Source.AUTO,
            source_id=source_id,
            description=description or config.description,
            nest=nest,
        )

        logger.info(
            "Points awarded: %d to %s for %s",
            points_to_award, user.email, activity_type,
        )

        # Evaluate badges asynchronously — keeps award_points() fast and ensures
        # a badge evaluation failure cannot roll back the point transaction.
        try:
            from .tasks import check_and_award_badges_async
            check_and_award_badges_async.delay(str(user.id))
        except Exception:
            # Celery unavailable (e.g. local dev without worker) — fall back to sync
            PointService.check_and_award_badges(user)

        return txn

    # ------------------------------------------------------------------
    # Manual Award
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def award_manual_points(
        eagle, eaglet, points: int, description: str, nest=None
    ) -> PointTransaction:
        """
        Eagle manually awards points to an Eaglet.
        Requires a description for audit trail.
        The Eagle must own a Nest that the Eaglet belongs to (admins bypass).
        """
        if eagle.role not in ("eagle", "admin"):
            raise PermissionDenied("Only Eagles or Admins can award points.")

        if points <= 0:
            raise ValidationError({"points": "Points must be a positive number."})

        if not description.strip():
            raise ValidationError({"description": "Description is required for manual awards."})

        # --- Authorization: verify Eagle→Eaglet relationship via Nest ---
        if not (eagle.is_staff or eagle.is_superuser):
            from apps.nests.models import Nest, NestMembership

            eagle_nest_ids = list(
                Nest.objects.filter(eagle=eagle).values_list("id", flat=True)
            )

            if nest is not None:
                # When a specific nest is provided, it must be owned by this Eagle
                if nest.id not in eagle_nest_ids:
                    raise PermissionDenied(
                        "You can only award points in Nests you own."
                    )
                # And the Eaglet must be an active member of that Nest
                if not NestMembership.objects.filter(
                    nest=nest, user=eaglet, status="active"
                ).exists():
                    raise ValidationError(
                        {"eaglet_id": "This Eaglet is not an active member of the specified Nest."}
                    )
            else:
                # No nest specified — Eaglet must be in at least one of Eagle's Nests
                if not NestMembership.objects.filter(
                    nest_id__in=eagle_nest_ids, user=eaglet, status="active"
                ).exists():
                    raise PermissionDenied(
                        "You can only award points to Eaglets in your Nests."
                    )

        # --- Governance: superadmin-set ceiling + daily budget (Phase 31-01) ---
        # Enforced HERE rather than in the serializer: this service is the single
        # chokepoint every caller passes through, so the limit cannot be bypassed
        # by a management command, signal, or future internal caller.
        # Admins are exempt — they set the policy. Reuses the SAME predicate as the
        # nest bypass above (is_staff or is_superuser) so stacked admins behave
        # consistently across both checks.
        is_admin_actor = eagle.is_staff or eagle.is_superuser
        policy = PointsPolicy.load()

        if policy.is_enforced and not is_admin_actor:
            if points > policy.max_manual_award:
                raise ValidationError({
                    "points": (
                        f"Maximum {policy.max_manual_award} points per award. "
                        f"You tried to award {points}."
                    )
                })

            used_today = PointService._manual_points_awarded_today(eagle)
            remaining = policy.daily_points_per_mentor - used_today
            if points > remaining:
                raise ValidationError({
                    "points": (
                        f"Daily limit reached. You have {max(remaining, 0)} of "
                        f"{policy.daily_points_per_mentor} points left to award today."
                    )
                })

        txn = PointTransaction.objects.create(
            user=eaglet,
            points=points,
            activity_type="manual_award",
            source=PointTransaction.Source.MANUAL,
            description=description,
            awarded_by=eagle,
            nest=nest,
        )

        logger.info(
            "Manual points: %d awarded to %s by %s — %s",
            points, eaglet.email, eagle.email, description,
        )

        PointService.check_and_award_badges(eaglet)
        return txn

    @staticmethod
    def _manual_points_awarded_today(eagle) -> int:
        """Total manual points this user has awarded today (UTC).

        Summed straight from the append-only ledger rather than a counter column,
        so the number can never drift from reality. Backed by the
        (awarded_by, -created_at) index added in migration 0009.
        UTC matches the Celery beat schedules used elsewhere.
        """
        today = timezone.now().date()
        total = PointTransaction.objects.filter(
            awarded_by=eagle,
            source=PointTransaction.Source.MANUAL,
            created_at__date=today,
        ).aggregate(total=Sum("points"))["total"]
        return total or 0

    @staticmethod
    def get_award_budget(eagle) -> dict:
        """Remaining manual-award allowance for this user.

        Shared by the enforcement path and `GET /points/award-budget/` so the
        figure shown in the UI is computed the same way as the one enforced.
        Admins are unlimited (they set the policy).
        """
        policy = PointsPolicy.load()
        is_admin_actor = eagle.is_staff or eagle.is_superuser

        if not policy.is_enforced or is_admin_actor:
            return {
                "max_per_award": None,
                "daily_limit": None,
                "used_today": PointService._manual_points_awarded_today(eagle),
                "remaining": None,
                "is_enforced": False,
            }

        used_today = PointService._manual_points_awarded_today(eagle)
        return {
            "max_per_award": policy.max_manual_award,
            "daily_limit": policy.daily_points_per_mentor,
            "used_today": used_today,
            "remaining": max(policy.daily_points_per_mentor - used_today, 0),
            "is_enforced": True,
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get_user_total_points(user) -> int:
        """Total lifetime points for a user."""
        return PointTransaction.objects.filter(user=user).aggregate(
            total=Sum("points")
        )["total"] or 0

    @staticmethod
    def get_user_rank(user, total: int | None = None) -> int:
        """Global rank based on total points (1-indexed).

        Pass ``total`` when the caller already computed the user's total
        (e.g. get_user_points_summary) to avoid re-aggregating it.
        """
        user_total = (
            total if total is not None
            else PointService.get_user_total_points(user)
        )
        if user_total == 0:
            return 0
        above = (
            PointTransaction.objects.filter(user__role="eaglet")
            .values("user")
            .annotate(total=Sum("points"))
            .filter(total__gt=user_total)
            .count()
        )
        return above + 1

    @staticmethod
    def get_user_points_breakdown(user) -> dict:
        """Points breakdown by activity type."""
        return dict(
            PointTransaction.objects.filter(user=user)
            .values_list("activity_type")
            .annotate(total=Sum("points"))
            .order_by("-total")
        )

    @staticmethod
    def get_user_transactions(user, limit: int = 50):
        """Recent point transactions for a user."""
        return PointTransaction.objects.filter(user=user)[:limit]

    @staticmethod
    def get_leaderboard(scope: str = "global", nest_id=None, period: str = "all"):
        """
        Build a leaderboard ranking.

        Args:
            scope: "global" or "nest"
            nest_id: Required when scope="nest"
            period: "all", "month", "week"
        """
        qs = PointTransaction.objects.filter(user__role="eaglet")

        if scope == "nest" and nest_id:
            qs = qs.filter(nest_id=nest_id)

        if period == "month":
            qs = qs.filter(created_at__gte=timezone.now() - timedelta(days=30))
        elif period == "week":
            qs = qs.filter(created_at__gte=timezone.now() - timedelta(days=7))

        return (
            qs.values("user__id", "user__first_name", "user__last_name", "user__role")
            .annotate(total_points=Sum("points"))
            .filter(total_points__gt=0)
            .order_by("-total_points")[:50]
        )

    # ------------------------------------------------------------------
    # Badges
    # ------------------------------------------------------------------

    @staticmethod
    def _build_badge_stats(user) -> dict:
        """
        Build a dict mapping each CriteriaType to the user's current stat value.
        Shared by check_and_award_badges() and get_badge_progress().
        """
        from apps.content.models import ContentProgress, AssignmentSubmission

        stats = {
            Badge.CriteriaType.POINTS_THRESHOLD: PointService.get_user_total_points(user),
            Badge.CriteriaType.COURSES_COMPLETED: ContentProgress.objects.filter(
                user=user, status="completed"
            ).values("content_item__module").distinct().count(),
            Badge.CriteriaType.ASSIGNMENTS_SUBMITTED: AssignmentSubmission.objects.filter(
                user=user
            ).count(),
            Badge.CriteriaType.STREAK_DAYS: PointService.get_user_streak(user),
        }

        # Community/quiz/events/nests stats — fall back to 0 if model unavailable
        try:
            from apps.nests.models import NestPost, NestPostComment
            stats[Badge.CriteriaType.COMMUNITY_CONTRIBUTIONS] = (
                NestPost.objects.filter(author=user).count() +
                NestPostComment.objects.filter(author=user).count()
            )
        except Exception:
            stats[Badge.CriteriaType.COMMUNITY_CONTRIBUTIONS] = 0

        try:
            from apps.content.models import ModuleAssignmentAttempt
            stats[Badge.CriteriaType.QUIZZES_PASSED] = ModuleAssignmentAttempt.objects.filter(
                user=user, passed=True
            ).count()
        except Exception:
            stats[Badge.CriteriaType.QUIZZES_PASSED] = 0

        try:
            from apps.nests.models import EventAttendance
            stats[Badge.CriteriaType.EVENTS_ATTENDED] = EventAttendance.objects.filter(
                user=user
            ).count()
        except Exception:
            stats[Badge.CriteriaType.EVENTS_ATTENDED] = 0

        try:
            from apps.nests.models import NestMembership
            stats[Badge.CriteriaType.NESTS_JOINED] = NestMembership.objects.filter(
                user=user, status="active"
            ).count()
        except Exception:
            stats[Badge.CriteriaType.NESTS_JOINED] = 0

        return stats

    @staticmethod
    def check_and_award_badges(user):
        """Check all badge criteria and award any newly earned badges (Eaglets only)."""
        if getattr(user, 'role', None) != 'eaglet':
            return

        earned_badge_ids = set(
            UserBadge.objects.filter(user=user).values_list("badge_id", flat=True)
        )
        stats = PointService._build_badge_stats(user)

        # ONE_TIME_EVENT and COMPETITIVE are never awarded inside this loop
        eligible_badges = Badge.objects.exclude(
            id__in=earned_badge_ids
        ).exclude(
            criteria_type__in=[
                Badge.CriteriaType.ONE_TIME_EVENT,
                Badge.CriteriaType.COMPETITIVE,
            ]
        )

        new_awards = [
            UserBadge(user=user, badge=badge)
            for badge in eligible_badges
            if stats.get(badge.criteria_type, 0) >= badge.criteria_value
        ]

        if new_awards:
            UserBadge.objects.bulk_create(new_awards, ignore_conflicts=True)
            for ub in new_awards:
                logger.info("Badge earned: %s by %s", ub.badge.name, user.email)
                PointService._notify_badge_earned(user, ub.badge)

    @staticmethod
    def _notify_badge_earned(user, badge):
        """Create a notification when a badge is earned (Eaglets only)."""
        try:
            from apps.notifications.services import NotificationService
            NotificationService.create_notification(
                recipient=user,
                notification_type="badge_earned",
                title=f"Badge Earned: {badge.name}",
                message=badge.description,
                action_url="/eaglet/badges",
            )
        except Exception as exc:
            logger.warning("Badge notification failed: %s", exc)

    @staticmethod
    def award_one_time_badge(user, slug: str) -> bool:
        """
        Award a ONE_TIME_EVENT badge by slug (Eaglets only).
        Returns True if the badge was newly awarded, False if already earned,
        not found, or user is not an Eaglet.
        """
        if getattr(user, "role", None) != "eaglet":
            return False
        try:
            badge = Badge.objects.get(
                slug=slug, criteria_type=Badge.CriteriaType.ONE_TIME_EVENT
            )
        except Badge.DoesNotExist:
            logger.debug("One-time badge not found: %s (seed_badges may not have run)", slug)
            return False
        _, created = UserBadge.objects.get_or_create(user=user, badge=badge)
        if created:
            logger.info("One-time badge earned: %s by %s", badge.name, user.email)
            PointService._notify_badge_earned(user, badge)
        return created

    @staticmethod
    def get_badge_progress(user, badge) -> int:
        """
        Return the user's current stat value for a given badge's criteria type.
        Used to render progress bars on locked badges in the frontend.
        """
        stats = PointService._build_badge_stats(user)
        return stats.get(badge.criteria_type, 0)

    @staticmethod
    def get_user_streak(user) -> int:
        """Calculate consecutive days the user has earned points.

        Distinct activity dates are computed DB-side (perf audit B2): the old
        version pulled EVERY transaction timestamp into Python and deduped
        there — unbounded transfer for active users. ``.dates()`` returns one
        row per distinct day; the slice bounds the worst case (a streak longer
        than 400 days would be truncated — acceptable).
        """
        dates = list(
            PointTransaction.objects.filter(user=user)
            .dates("created_at", "day", order="DESC")[:400]
        )

        if not dates:
            return 0

        today = timezone.now().date()

        if dates[0] < today - timedelta(days=1):
            return 0

        streak = 1
        for i in range(1, len(dates)):
            if dates[i - 1] - dates[i] == timedelta(days=1):
                streak += 1
            else:
                break

        return streak

    @staticmethod
    def get_user_badges(user):
        """Return badges earned by a user."""
        return UserBadge.objects.filter(user=user).select_related("badge")

    SUMMARY_CACHE_TTL = 60  # seconds

    @staticmethod
    def summary_cache_key(user_id) -> str:
        return f"points_summary:{user_id}"

    @staticmethod
    def invalidate_summary_cache(user_id) -> None:
        """Drop the cached summary — called from points/badge signals."""
        cache.delete(PointService.summary_cache_key(user_id))

    @staticmethod
    def get_user_points_summary(user) -> dict:
        """
        All points stats for the 'my points' dashboard, consolidated + cached.

        Perf audit B1/B2: was 6 queries per request (total computed twice —
        once standalone, once inside rank). Now 4 queries:
          1. breakdown by activity type (total derived by summing it)
          2. badge count
          3. rank (reuses the derived total)
          4. streak (DB-side distinct dates)
        Result cached for SUMMARY_CACHE_TTL; invalidated by signals when a
        new PointTransaction or UserBadge lands, so awards show immediately.
        """
        key = PointService.summary_cache_key(user.id)
        cached = cache.get(key)
        if cached is not None:
            return cached

        # 1. Breakdown — single GROUP BY; total derives from it for free.
        breakdown_qs = (
            PointTransaction.objects.filter(user=user)
            .values("activity_type")
            .annotate(total=Sum("points"))
        )
        breakdown = {item["activity_type"]: item["total"] for item in breakdown_qs}
        total = sum(breakdown.values())

        # 2. Badge count
        badge_count = UserBadge.objects.filter(user=user).count()

        # 3. Rank — reuse the total instead of re-aggregating it.
        rank = PointService.get_user_rank(user, total=total)

        # 4. Streak — bounded, DB-side distinct dates.
        streak = PointService.get_user_streak(user)

        summary = {
            "total_points": total,
            "streak_days": streak,
            "breakdown": breakdown,
            "rank": rank,
            "badge_count": badge_count,
        }
        cache.set(key, summary, PointService.SUMMARY_CACHE_TTL)
        return summary

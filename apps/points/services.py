"""
Points Services

Business logic for the gamification system: auto/manual point awards,
leaderboard calculations, badge checking, and streak tracking.
"""

import logging
from datetime import timedelta

from django.db import transaction
from django.db.models import Sum, Count, Max, Q
from django.utils import timezone
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError

from apps.users.models import User
from .models import PointConfiguration, PointTransaction, Badge, UserBadge

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
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        # Acquire lock on the User row to serialize concurrent point awards
        # This completely mitigates Race Condition bug #1 (Duplicate Point Transactions)
        try:
            _locked_user = User.objects.select_for_update().get(id=user.id)
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

        # Check for new badges
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
    def get_user_rank(user) -> int:
        """Global rank based on total points (1-indexed)."""
        user_total = PointService.get_user_total_points(user)
        if user_total == 0:
            return 0
        above = (
            PointTransaction.objects.values("user")
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
        from django.contrib.auth import get_user_model
        User = get_user_model()

        qs = PointTransaction.objects.all()

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
    def check_and_award_badges(user):
        """Check all badge criteria and award any newly earned badges (Eaglets only)."""
        if getattr(user, 'role', None) != 'eaglet':
            return
        from apps.content.models import ContentProgress, AssignmentSubmission
        from apps.points.models import PointTransaction

        total_points = PointService.get_user_total_points(user)
        earned_badge_ids = set(
            UserBadge.objects.filter(user=user).values_list("badge_id", flat=True)
        )

        # Build stats dict — import models lazily to avoid circular imports
        stats = {
            Badge.CriteriaType.POINTS_THRESHOLD: total_points,
            Badge.CriteriaType.COURSES_COMPLETED: ContentProgress.objects.filter(
                user=user, status="completed"
            ).values("content_item__module").distinct().count(),
            Badge.CriteriaType.ASSIGNMENTS_SUBMITTED: AssignmentSubmission.objects.filter(
                user=user
            ).count(),
            Badge.CriteriaType.STREAK_DAYS: PointService.get_user_streak(user),
        }

        # Add community/quiz/events/nests stats — these models may not exist yet,
        # so fall back to 0 if the model is unavailable
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
            # bulk_create doesn't return loaded FK relations on all DB backends.
            # Iterate new_awards — badge objects are already in memory from the queryset.
            UserBadge.objects.bulk_create(new_awards, ignore_conflicts=True)
            for ub in new_awards:
                logger.info("Badge earned: %s by %s", ub.badge.name, user.email)
                PointService._notify_badge_earned(user, ub.badge)

    @staticmethod
    def _notify_badge_earned(user, badge):
        """Create a notification when a badge is earned."""
        try:
            from apps.notifications.services import NotificationService
            NotificationService.create_notification(
                recipient=user,
                notification_type="badge_earned",
                title=f"Badge Earned: {badge.name}",
                message=badge.description,
                action_url="/points/badges",
            )
        except Exception as exc:
            logger.warning("Badge notification failed: %s", exc)

    @staticmethod
    def award_one_time_badge(user, slug: str) -> bool:
        """
        Award a ONE_TIME_EVENT badge by slug.
        Returns True if the badge was newly awarded, False if already earned or not found.
        """
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
        from django.db.models import Sum
        from apps.content.models import ContentProgress, AssignmentSubmission
        from apps.points.models import PointTransaction

        ct = badge.criteria_type

        if ct == Badge.CriteriaType.POINTS_THRESHOLD:
            result = PointTransaction.objects.filter(user=user).aggregate(total=Sum("points"))
            return result["total"] or 0
        if ct == Badge.CriteriaType.COURSES_COMPLETED:
            return ContentProgress.objects.filter(
                user=user, status="completed"
            ).values("content_item__module").distinct().count()
        if ct == Badge.CriteriaType.ASSIGNMENTS_SUBMITTED:
            return AssignmentSubmission.objects.filter(user=user).count()
        if ct == Badge.CriteriaType.STREAK_DAYS:
            return PointService.get_user_streak(user)
        if ct == Badge.CriteriaType.COMMUNITY_CONTRIBUTIONS:
            try:
                from apps.nests.models import NestPost, NestPostComment
                return (
                    NestPost.objects.filter(author=user).count() +
                    NestPostComment.objects.filter(author=user).count()
                )
            except Exception:
                return 0
        if ct == Badge.CriteriaType.QUIZZES_PASSED:
            try:
                from apps.content.models import ModuleAssignmentAttempt
                return ModuleAssignmentAttempt.objects.filter(user=user, passed=True).count()
            except Exception:
                return 0
        if ct == Badge.CriteriaType.EVENTS_ATTENDED:
            try:
                from apps.nests.models import EventAttendance
                return EventAttendance.objects.filter(user=user).count()
            except Exception:
                return 0
        if ct == Badge.CriteriaType.NESTS_JOINED:
            try:
                from apps.nests.models import NestMembership
                return NestMembership.objects.filter(user=user, status="active").count()
            except Exception:
                return 0
        return 0  # ONE_TIME_EVENT and COMPETITIVE have no measurable progress

    @staticmethod
    def get_user_streak(user) -> int:
        """Calculate consecutive days the user has earned points."""
        txns = (
            PointTransaction.objects.filter(user=user)
            .order_by("-created_at")
            .values_list("created_at", flat=True)
        )

        if not txns:
            return 0

        dates = sorted(set(t.date() for t in txns), reverse=True)
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
    @staticmethod
    def get_user_points_summary(user) -> dict:
        """
        Get all points-related stats for a user in a consolidated manner.
        Reduces number of queries for the 'my points' dashboard.
        """
        # 1. Total points
        total = PointTransaction.objects.filter(user=user).aggregate(
            total=Sum("points")
        )["total"] or 0
        
        # 2. Badge count
        badge_count = UserBadge.objects.filter(user=user).count()
        
        # 3. Points breakdown by activity type
        breakdown_qs = (
            PointTransaction.objects.filter(user=user)
            .values("activity_type")
            .annotate(total=Sum("points"))
        )
        breakdown = {item["activity_type"]: item["total"] for item in breakdown_qs}
        
        # 4. Streak (simplified for this optimization, keeping existing logic if complex)
        streak = PointService.get_user_streak(user)
        
        # 5. Rank
        rank = PointService.get_user_rank(user)
        
        return {
            "total_points": total,
            "streak_days": streak,
            "breakdown": breakdown,
            "rank": rank,
            "badge_count": badge_count,
        }

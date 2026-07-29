"""
Points Serializers

Read and write serializers for point transactions, leaderboard,
badges, and configuration.
"""

from rest_framework import serializers


from .models import PointConfiguration, PointsPolicy, PointTransaction, Badge, UserBadge


class PointConfigurationSerializer(serializers.ModelSerializer):
    """Point configuration read/write serializer."""

    display_name = serializers.CharField(
        source="get_activity_type_display", read_only=True
    )

    class Meta:
        model = PointConfiguration
        fields = [
            "id", "activity_type", "display_name", "points_value",
            "is_active", "description",
        ]
        read_only_fields = ["id", "activity_type"]


class PointTransactionSerializer(serializers.ModelSerializer):
    """Read-only point transaction."""

    awarded_by_name = serializers.CharField(
        source="awarded_by.full_name", read_only=True, default=""
    )

    class Meta:
        model = PointTransaction
        fields = [
            "id", "points", "activity_type", "source", "source_id",
            "description", "awarded_by_name", "nest", "created_at",
        ]
        read_only_fields = fields


class ManualPointAwardSerializer(serializers.Serializer):
    """Write serializer for manual point awards.

    NOTE: `max_value` here is only a loose sanity bound against absurd input. The
    REAL ceiling is `PointsPolicy.max_manual_award`, enforced in
    `PointService.award_manual_points()` — the chokepoint every caller passes
    through. Do not re-add a hardcoded business limit here: serializer validation
    is bypassable by any non-API caller (management commands, signals, internal
    services), which is exactly the hole this replaced.
    """

    eaglet_id = serializers.UUIDField()
    points = serializers.IntegerField(min_value=1, max_value=100000)
    description = serializers.CharField(max_length=250, min_length=5)
    nest_id = serializers.UUIDField(required=False)


class PointsPolicySerializer(serializers.ModelSerializer):
    """Superadmin read/write of the manual-award governance policy."""

    class Meta:
        model = PointsPolicy
        fields = [
            "id", "max_manual_award", "daily_points_per_mentor",
            "is_enforced", "updated_at",
        ]
        read_only_fields = ["id", "updated_at"]


class AwardBudgetSerializer(serializers.Serializer):
    """Remaining manual-award allowance for the requesting user."""

    max_per_award = serializers.IntegerField(allow_null=True)
    daily_limit = serializers.IntegerField(allow_null=True)
    used_today = serializers.IntegerField()
    remaining = serializers.IntegerField(allow_null=True)
    is_enforced = serializers.BooleanField()


class LeaderboardEntrySerializer(serializers.Serializer):
    """Single leaderboard entry."""

    rank = serializers.IntegerField()
    user = serializers.SerializerMethodField()
    first_name = serializers.CharField(source="user__first_name")
    last_name = serializers.CharField(source="user__last_name")
    role = serializers.CharField(source="user__role")
    total_points = serializers.IntegerField()

    def get_user(self, obj):
        return {"id": obj.get("user__id")}


class BadgeSerializer(serializers.ModelSerializer):
    """Badge read serializer — includes per-user progress and earned status."""

    progress = serializers.SerializerMethodField()
    earned = serializers.SerializerMethodField()
    earned_at = serializers.SerializerMethodField()

    class Meta:
        model = Badge
        fields = [
            "id", "slug", "name", "description", "icon",
            "criteria_type", "criteria_value",
            "earned", "earned_at", "progress",
        ]
        read_only_fields = fields

    def _get_user_badge(self, obj):
        """Cached lookup of UserBadge for current user + badge."""
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return None
        cache_key = f"_ub_{obj.id}"
        if not hasattr(request, "_badge_cache"):
            request._badge_cache = {}
        if cache_key not in request._badge_cache:
            from apps.points.models import UserBadge
            request._badge_cache[cache_key] = UserBadge.objects.filter(
                user=request.user, badge=obj
            ).first()
        return request._badge_cache[cache_key]

    def get_earned(self, obj):
        return self._get_user_badge(obj) is not None

    def get_earned_at(self, obj):
        ub = self._get_user_badge(obj)
        return ub.earned_at if ub else None

    def get_progress(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return 0
        from apps.points.services import PointService
        return PointService.get_badge_progress(request.user, obj)


class UserBadgeSerializer(serializers.ModelSerializer):
    """User badge with nested badge info."""

    badge = BadgeSerializer(read_only=True)

    class Meta:
        model = UserBadge
        fields = ["id", "badge", "earned_at"]
        read_only_fields = fields

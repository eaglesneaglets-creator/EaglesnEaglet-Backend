"""
Nest Serializers

Read and write serializers for Nest, Membership, Request, Post,
Resource, and Event models.
"""

from django.db.models import Prefetch
from rest_framework import serializers

from apps.users.models import User

from .models import (
    Nest,
    NestMembership,
    MentorshipRequest,
    NestPost,
    NestPostComment,
    NestResource,
    NestEvent,
)
from .models_program import (
    MenteeLevelConfig,
    Program,
    ProgramEnrollment,
    ProgramExitRequest,
    ProgramObjective,
    ProgramObjectiveRule,
)


# ---------------------------------------------------------------------------
# Lightweight user serializer for nesting
# ---------------------------------------------------------------------------

class UserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user representation for nested serializers."""

    full_name = serializers.CharField(read_only=True)
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "first_name", "last_name", "full_name", "role", "avatar_url"]
        read_only_fields = fields

    def get_avatar_url(self, obj):
        """Return the best available avatar URL."""
        if obj.avatar:
            try:
                return obj.avatar.url
            except Exception:
                pass
        return obj.profile_picture_url or None


# ---------------------------------------------------------------------------
# Mentor profile (Phase 28-01) — embedded in nest discovery so the mentee
# browse card can render person-first mentor data sourced from MentorKYC.
# ---------------------------------------------------------------------------

class MentorProfileSerializer(serializers.Serializer):
    """Read-only view of a mentor's KYC-sourced public profile."""

    display_picture = serializers.CharField(read_only=True, allow_blank=True, default="")
    current_occupation = serializers.CharField(read_only=True, allow_blank=True, default="")
    area_of_expertise = serializers.CharField(read_only=True, allow_blank=True, default="")
    profile_description = serializers.CharField(read_only=True, allow_blank=True, default="")
    years_of_service = serializers.IntegerField(read_only=True, default=0)
    location = serializers.CharField(read_only=True, allow_blank=True, default="")
    mentorship_types = serializers.SerializerMethodField()
    kyc_verified = serializers.SerializerMethodField()

    def get_mentorship_types(self, obj):
        return getattr(obj, "mentorship_types", None) or []

    def get_kyc_verified(self, obj):
        return getattr(obj, "status", None) == "approved"


# ---------------------------------------------------------------------------
# Nest
# ---------------------------------------------------------------------------

class NestListSerializer(serializers.ModelSerializer):
    """Compact nest representation for list views."""

    eagle_name = serializers.CharField(source="eagle.full_name", read_only=True)
    member_count = serializers.IntegerField(source="annotated_member_count", read_only=True)
    mentor_profile = serializers.SerializerMethodField()

    class Meta:
        model = Nest
        fields = [
            "id", "name", "slug", "description", "industry_focus",
            "banner_image", "eagle", "eagle_name", "privacy",
            "member_count", "is_active", "created_at", "mentor_profile",
        ]
        read_only_fields = ["id", "slug", "eagle", "created_at"]

    def get_mentor_profile(self, obj):
        """Embed the eagle's MentorKYC as a person-first profile, or None.

        Null-safe: public nests are auto-created on KYC approval, but a missing
        KYC row must not break the discovery list.
        """
        kyc = getattr(obj.eagle, "mentor_kyc", None)
        if kyc is None:
            return None
        return MentorProfileSerializer(kyc).data


class DiscoveryObjectiveSerializer(serializers.Serializer):
    """Mentee-facing objective summary embedded in NestDetailSerializer.current_program."""

    id = serializers.UUIDField()
    title = serializers.CharField()
    rule_summary = serializers.SerializerMethodField()

    def get_rule_summary(self, obj):
        # Local import avoids circular dependency with services <-> serializers.
        from .services import build_objective_rule_summary
        return build_objective_rule_summary(obj)


class DiscoveryProgramSerializer(serializers.Serializer):
    """Mentee-facing program summary embedded in Nest discovery payload."""

    id = serializers.UUIDField()
    name = serializers.CharField()
    description = serializers.CharField()
    objectives = DiscoveryObjectiveSerializer(many=True)


class NestDetailSerializer(serializers.ModelSerializer):
    """Full nest details with eagle info."""

    eagle_details = UserMinimalSerializer(source="eagle", read_only=True)
    member_count = serializers.IntegerField(source="annotated_member_count", read_only=True)
    is_full = serializers.BooleanField(source="annotated_is_full", read_only=True)
    current_program = serializers.SerializerMethodField()

    class Meta:
        model = Nest
        fields = [
            "id", "name", "slug", "description", "industry_focus",
            "banner_image", "eagle_details", "privacy", "allow_referrals",
            "meeting_link", "max_members", "member_count", "is_full",
            "is_active", "current_program",
            "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "slug", "eagle_details", "current_program",
            "created_at", "updated_at",
        ]

    def get_current_program(self, obj):
        # Pick first active program for this nest (single-active-per-nest invariant).
        # Uses prefetched programs queryset when available to avoid N+1.
        programs = getattr(obj, "_prefetched_objects_cache", {}).get("programs")
        if programs is not None:
            active = next(
                (p for p in programs if p.status == "active"), None,
            )
        else:
            active = obj.programs.filter(status="active").first()
        if active is None:
            return None
        return DiscoveryProgramSerializer(active).data


class NestCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating / updating a Nest."""

    class Meta:
        model = Nest
        fields = [
            "name", "description", "industry_focus", "banner_image",
            "privacy", "allow_referrals", "meeting_link", "max_members",
        ]

    def validate_max_members(self, value):
        if value < 2:
            raise serializers.ValidationError("Max members must be at least 2.")
        if value > 200:
            raise serializers.ValidationError("Max members cannot exceed 200.")
        return value


# ---------------------------------------------------------------------------
# Membership
# ---------------------------------------------------------------------------

class MembershipSerializer(serializers.ModelSerializer):
    """Read-only membership with nested user, points, and current module."""

    user_details = UserMinimalSerializer(source="user", read_only=True)
    total_points = serializers.SerializerMethodField()
    current_module = serializers.SerializerMethodField()

    class Meta:
        model = NestMembership
        fields = [
            "id", "user_details", "role", "status", "joined_at",
            "progress_percentage", "total_points", "current_module", "created_at",
        ]
        read_only_fields = fields

    def get_total_points(self, obj):
        """Sum of all points earned by this user."""
        from django.db.models import Sum
        from apps.points.models import PointTransaction
        result = PointTransaction.objects.filter(
            user=obj.user
        ).aggregate(total=Sum("points"))
        return result["total"] or 0

    def get_current_module(self, obj):
        """Title of the most recently accessed module in this nest."""
        from apps.content.models import ContentProgress
        latest = (
            ContentProgress.objects.filter(
                user=obj.user,
                content_item__module__nest=obj.nest,
            )
            .select_related("content_item__module")
            .order_by("-updated_at")
            .first()
        )
        if latest:
            return latest.content_item.module.title
        return None


# ---------------------------------------------------------------------------
# Mentorship Request
# ---------------------------------------------------------------------------

class MentorshipRequestSerializer(serializers.ModelSerializer):
    """Read representation of a mentorship request."""

    eaglet_details = UserMinimalSerializer(source="eaglet", read_only=True)
    reviewed_by_details = UserMinimalSerializer(source="reviewed_by", read_only=True)
    nest_name = serializers.CharField(source="nest.name", read_only=True)

    class Meta:
        model = MentorshipRequest
        fields = [
            "id", "nest", "nest_name", "eaglet_details", "status", "message",
            "reviewed_by_details", "reviewed_at", "created_at",
        ]
        read_only_fields = fields


# ---------------------------------------------------------------------------
# Nest Post & Comment
# ---------------------------------------------------------------------------

class ReplySerializer(serializers.ModelSerializer):
    """Flat reply serializer — no further nesting."""

    author_details = UserMinimalSerializer(source="author", read_only=True)

    class Meta:
        model = NestPostComment
        fields = ["id", "author_details", "content", "created_at"]
        read_only_fields = fields


class NestPostCommentSerializer(serializers.ModelSerializer):
    """Top-level comment serializer with prefetched replies embedded."""

    author_details = UserMinimalSerializer(source="author", read_only=True)
    replies = ReplySerializer(many=True, read_only=True)

    class Meta:
        model = NestPostComment
        fields = ["id", "author_details", "content", "created_at", "replies"]
        read_only_fields = fields


class NestPostSerializer(serializers.ModelSerializer):
    """Post serializer — comments top-level only, liked_by_me per-request."""

    author_details = UserMinimalSerializer(source="author", read_only=True)
    comments = serializers.SerializerMethodField()
    liked_by_me = serializers.SerializerMethodField()

    def get_liked_by_me(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False
        # Feed list annotates liked_by_me on the queryset (see CommunityService.get_nest_posts).
        if hasattr(obj, "liked_by_me"):
            return obj.liked_by_me
        return obj.likes.filter(user=request.user).exists()

    def get_comments(self, obj):
        top_level = (
            obj.comments.filter(parent=None)
            .select_related("author")
            .prefetch_related(
                Prefetch("replies", queryset=NestPostComment.objects.select_related("author").order_by("created_at"))
            )
            .order_by("created_at")
        )
        return NestPostCommentSerializer(top_level, many=True).data

    class Meta:
        model = NestPost
        fields = [
            "id", "post_type", "content", "attachment_url",
            "attachment_type", "author_details", "likes_count", "liked_by_me",
            "comments_count", "comments", "created_at",
        ]
        read_only_fields = [
            "id", "author_details", "likes_count", "liked_by_me",
            "comments_count", "created_at",
        ]


class NestPostCreateSerializer(serializers.Serializer):
    """Write serializer for creating a post."""

    post_type = serializers.ChoiceField(
        choices=NestPost.PostType.choices, default="post"
    )
    content = serializers.CharField(max_length=5000)
    attachment_url = serializers.URLField(required=False, allow_blank=True)
    attachment_type = serializers.CharField(required=False, allow_blank=True, max_length=10)


class NestPostLikeToggleResponseSerializer(serializers.Serializer):
    liked = serializers.BooleanField()
    likes_count = serializers.IntegerField()


class MediaUploadResponseSerializer(serializers.Serializer):
    url = serializers.URLField()
    type = serializers.ChoiceField(choices=["image", "video", "file"])


# ---------------------------------------------------------------------------
# Nest Resource
# ---------------------------------------------------------------------------

class NestResourceSerializer(serializers.ModelSerializer):
    """Resource serializer."""

    uploaded_by = UserMinimalSerializer(read_only=True)

    class Meta:
        model = NestResource
        fields = [
            "id", "title", "file_url", "file_type", "file_size",
            "uploaded_by", "created_at",
        ]
        read_only_fields = ["id", "uploaded_by", "created_at"]


class NestResourceCreateSerializer(serializers.Serializer):
    """Write serializer for uploading a resource."""

    title = serializers.CharField(max_length=200)
    file_url = serializers.URLField()
    file_type = serializers.ChoiceField(choices=NestResource.FileType.choices)
    file_size = serializers.IntegerField(min_value=0, default=0)


# ---------------------------------------------------------------------------
# Nest Event
# ---------------------------------------------------------------------------

class NestEventSerializer(serializers.ModelSerializer):
    """Event serializer."""

    created_by = UserMinimalSerializer(read_only=True)

    class Meta:
        model = NestEvent
        fields = [
            "id", "title", "description", "event_date", "meeting_link",
            "event_type", "created_by", "created_at",
        ]
        read_only_fields = ["id", "created_by", "created_at"]


class NestEventCreateSerializer(serializers.Serializer):
    """Write serializer for creating an event."""

    title = serializers.CharField(max_length=200)
    description = serializers.CharField(required=False, allow_blank=True)
    event_date = serializers.DateTimeField()
    meeting_link = serializers.URLField(required=False, allow_blank=True)
    event_type = serializers.ChoiceField(
        choices=NestEvent.EventType.choices, default="session"
    )


# ---------------------------------------------------------------------------
# Program serializers (plan 14-01)
# ---------------------------------------------------------------------------


class ProgramObjectiveRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProgramObjectiveRule
        fields = ["id", "rule_type", "target", "config"]
        read_only_fields = ["id"]

    def validate_target(self, value):
        if value < 1:
            raise serializers.ValidationError("Target must be at least 1.")
        return value

    def validate_config(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("Config must be a JSON object.")
        return value


class ProgramObjectiveSerializer(serializers.ModelSerializer):
    rules = ProgramObjectiveRuleSerializer(many=True, read_only=True)

    class Meta:
        model = ProgramObjective
        fields = ["id", "title", "description", "order", "rules"]
        read_only_fields = ["id"]


class ProgramSerializer(serializers.ModelSerializer):
    """Read serializer with nested objectives + nest label."""

    objectives = ProgramObjectiveSerializer(many=True, read_only=True)
    nest_name = serializers.CharField(source="nest.name", read_only=True)

    class Meta:
        model = Program
        fields = [
            "id", "nest", "nest_name", "name", "description",
            "status", "activated_at", "archived_at",
            "objectives", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "nest_name", "activated_at", "archived_at",
            "objectives", "created_at", "updated_at",
        ]


class ProgramWriteSerializer(serializers.ModelSerializer):
    """Create/update serializer. Excludes nested objectives — managed via separate endpoints."""

    class Meta:
        model = Program
        fields = ["nest", "name", "description", "status"]

    def validate_status(self, value):
        instance = getattr(self, "instance", None)
        if instance and instance.status == Program.Status.ARCHIVED and value != Program.Status.ARCHIVED:
            raise serializers.ValidationError("Archived programs cannot be reactivated.")
        return value


# ---------------------------------------------------------------------------
# Program enrollment serializers (plan 14-02)
# ---------------------------------------------------------------------------


class ProgramEnrollmentSerializer(serializers.ModelSerializer):
    """Read serializer for ProgramEnrollment with mentee + program labels."""

    mentee_details = UserMinimalSerializer(source="mentee", read_only=True)
    program_name = serializers.CharField(source="program.name", read_only=True)
    nest_id = serializers.CharField(source="program.nest_id", read_only=True)
    nest_name = serializers.CharField(source="program.nest.name", read_only=True)

    class Meta:
        model = ProgramEnrollment
        fields = [
            "id", "program", "program_name", "nest_id", "nest_name",
            "mentee", "mentee_details", "status", "application_message",
            "requested_at", "started_at", "ended_at",
            "reviewed_by", "ended_by", "exit_reason",
            "rules_snapshot", "created_at", "updated_at",
        ]
        read_only_fields = fields


class ProgramApplyInputSerializer(serializers.Serializer):
    """Input for nest enroll endpoint."""

    message = serializers.CharField(required=False, allow_blank=True, max_length=1000)


class ProgramEnrollmentDecisionInputSerializer(serializers.Serializer):
    """Reason payload for reject / release / decline actions."""

    reason = serializers.CharField(required=False, allow_blank=True, max_length=1000)


class ProgramExitRequestInputSerializer(serializers.Serializer):
    """Mentee opt-out request payload."""

    reason = serializers.CharField(required=True, max_length=1000)


class ProgramExitDecisionInputSerializer(serializers.Serializer):
    """Mentor decision on exit request."""

    approve = serializers.BooleanField(required=True)
    note = serializers.CharField(required=False, allow_blank=True, max_length=1000)


class ProgramExitRequestSerializer(serializers.ModelSerializer):
    """Read serializer for ProgramExitRequest."""

    requested_by_details = UserMinimalSerializer(source="requested_by", read_only=True)
    decided_by_details = UserMinimalSerializer(source="decided_by", read_only=True)

    class Meta:
        model = ProgramExitRequest
        fields = [
            "id", "enrollment", "requested_by", "requested_by_details",
            "reason", "status", "decided_by", "decided_by_details",
            "decided_at", "decision_note", "created_at", "updated_at",
        ]
        read_only_fields = fields


# ---------------------------------------------------------------------------
# MenteeLevelConfig (plan 14-04)
# ---------------------------------------------------------------------------


class MenteeLevelConfigSerializer(serializers.ModelSerializer):
    """Read view of a single level row. `level` + `unlocks_mentor_application`
    are immutable once seeded; only `name`, `points_required`, `description`
    are bulk-patchable."""

    class Meta:
        model = MenteeLevelConfig
        fields = [
            "level", "name", "points_required",
            "unlocks_mentor_application", "description",
            "created_at", "updated_at",
        ]
        read_only_fields = [
            "level", "unlocks_mentor_application",
            "created_at", "updated_at",
        ]


class MenteeLevelConfigBulkUpdateSerializer(serializers.Serializer):
    """Validates a bulk PATCH payload. Enforces:
       - every referenced level exists (1..5)
       - resulting full ordered list is monotonically increasing in points_required
       - level 5's unlocks_mentor_application cannot be flipped to False
    """

    levels = serializers.ListField(
        child=serializers.DictField(), allow_empty=False,
    )

    def validate(self, attrs):
        from .models_program import MenteeLevelConfig

        rows = attrs["levels"]
        existing = {c.level: c for c in MenteeLevelConfig.objects.order_by("level")}

        proposed = {lvl: cfg.points_required for lvl, cfg in existing.items()}
        for row in rows:
            level = row.get("level")
            if level not in existing:
                raise serializers.ValidationError(
                    {"levels": f"level={level} does not exist."}
                )
            if "points_required" in row:
                pr = row["points_required"]
                if not isinstance(pr, int) or pr < 0:
                    raise serializers.ValidationError(
                        {"levels": f"level={level} points_required must be non-negative int."}
                    )
                proposed[level] = pr
            if (level == 5
                    and row.get("unlocks_mentor_application") is False):
                raise serializers.ValidationError(
                    {"levels": "Cannot disable mentor application unlock on level 5."}
                )

        ordered = [proposed[k] for k in sorted(proposed)]
        for i in range(1, len(ordered)):
            if ordered[i] < ordered[i - 1]:
                raise serializers.ValidationError(
                    {"levels": "points_required must be monotonically non-decreasing across levels."}
                )

        return attrs

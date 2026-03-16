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
# Nest
# ---------------------------------------------------------------------------

class NestListSerializer(serializers.ModelSerializer):
    """Compact nest representation for list views."""

    eagle_name = serializers.CharField(source="eagle.full_name", read_only=True)
    member_count = serializers.IntegerField(source="annotated_member_count", read_only=True)

    class Meta:
        model = Nest
        fields = [
            "id", "name", "slug", "description", "industry_focus",
            "banner_image", "eagle", "eagle_name", "privacy",
            "member_count", "is_active", "created_at",
        ]
        read_only_fields = ["id", "slug", "eagle", "created_at"]


class NestDetailSerializer(serializers.ModelSerializer):
    """Full nest details with eagle info."""

    eagle_details = UserMinimalSerializer(source="eagle", read_only=True)
    member_count = serializers.IntegerField(source="annotated_member_count", read_only=True)
    is_full = serializers.BooleanField(source="annotated_is_full", read_only=True)

    class Meta:
        model = Nest
        fields = [
            "id", "name", "slug", "description", "industry_focus",
            "banner_image", "eagle_details", "privacy", "allow_referrals",
            "meeting_link", "max_members", "member_count", "is_full",
            "is_active", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "slug", "eagle_details", "created_at", "updated_at",
        ]


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

    class Meta:
        model = MentorshipRequest
        fields = [
            "id", "nest", "eaglet_details", "status", "message",
            "reviewed_by_details", "reviewed_at", "created_at",
        ]
        read_only_fields = fields


class MentorshipRequestCreateSerializer(serializers.Serializer):
    """Serializer for creating a mentorship request."""

    message = serializers.CharField(required=False, allow_blank=True, max_length=1000)


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

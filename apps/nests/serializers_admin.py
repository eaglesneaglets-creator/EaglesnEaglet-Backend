"""
Admin nest oversight serializers (Phase 27-01).

Separate from serializers.py (mentor/eaglet surface) so the admin payloads —
which expose more (all-nests, derived status, activity) — stay isolated.
"""

from rest_framework import serializers

from apps.users.models import User

from .models import Nest, NestMembership, NestResource
from .models_activity import NestActivity
from .serializers import UserMinimalSerializer


def _derive_status(nest) -> str:
    """UI status: archived / forming / active.

    - is_active=False (or soft-deleted)  → 'archived'
    - active, 0 members                  → 'forming'
    - active, 1+ members                 → 'active'
    ('completed' is not a stored state in v1; a mentor archives when done.)
    """
    if not nest.is_active or getattr(nest, "is_deleted", False):
        return "archived"
    count = getattr(nest, "annotated_member_count", None)
    if count is None:
        count = nest.member_count
    return "forming" if count == 0 else "active"


class AdminNestListSerializer(serializers.ModelSerializer):
    """Compact all-nests row for the admin list page."""

    eagle = UserMinimalSerializer(read_only=True)
    member_count = serializers.IntegerField(source="annotated_member_count", read_only=True)
    status = serializers.SerializerMethodField()

    class Meta:
        model = Nest
        fields = [
            "id", "name", "slug", "description", "category", "privacy",
            "eagle", "member_count", "max_members", "is_active", "status",
            "created_at",
        ]
        read_only_fields = fields

    def get_status(self, obj):
        return _derive_status(obj)


class NestActivitySerializer(serializers.ModelSerializer):
    """A single audit-log row for the Activity tab."""

    actor = UserMinimalSerializer(read_only=True)

    class Meta:
        model = NestActivity
        fields = ["id", "actor", "action_type", "target", "metadata", "created_at"]
        read_only_fields = fields


class AdminNestResourceSerializer(serializers.ModelSerializer):
    """Shared content row (view-only) for the admin detail page."""

    uploaded_by = UserMinimalSerializer(read_only=True)

    class Meta:
        model = NestResource
        fields = ["id", "title", "file_url", "uploaded_by", "created_at"]
        read_only_fields = fields


class AdminMembershipSerializer(serializers.ModelSerializer):
    """Member row with the user detail the admin panel needs."""

    user = UserMinimalSerializer(read_only=True)

    class Meta:
        model = NestMembership
        fields = ["id", "user", "role", "status", "joined_at", "progress_percentage"]
        read_only_fields = fields


class AdminNestDetailSerializer(AdminNestListSerializer):
    """Full nest detail: list fields + members + shared content + recent activity."""

    members = serializers.SerializerMethodField()
    shared_content = serializers.SerializerMethodField()
    recent_activity = serializers.SerializerMethodField()

    class Meta(AdminNestListSerializer.Meta):
        fields = AdminNestListSerializer.Meta.fields + [
            "industry_focus", "meeting_link", "members",
            "shared_content", "recent_activity",
        ]

    def get_members(self, obj):
        qs = obj.memberships.filter(
            status=NestMembership.Status.ACTIVE
        ).select_related("user")
        return AdminMembershipSerializer(qs, many=True).data

    def get_shared_content(self, obj):
        qs = obj.resources.select_related("uploaded_by")[:50]
        return AdminNestResourceSerializer(qs, many=True).data

    def get_recent_activity(self, obj):
        qs = obj.activities.select_related("actor")[:10]
        return NestActivitySerializer(qs, many=True).data


class AdminNestCreateSerializer(serializers.Serializer):
    """Write serializer for create-on-behalf. `eagle_id` resolves to a User."""

    name = serializers.CharField(max_length=150)
    description = serializers.CharField(required=False, allow_blank=True)
    category = serializers.ChoiceField(choices=Nest.Category.choices, default=Nest.Category.OTHER)
    privacy = serializers.ChoiceField(choices=Nest.Privacy.choices, default=Nest.Privacy.PUBLIC)
    max_members = serializers.IntegerField(min_value=1, max_value=500, default=50)
    eagle_id = serializers.UUIDField()

    def validate_eagle_id(self, value):
        try:
            eagle = User.objects.get(pk=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Mentor not found.")
        if eagle.role != "eagle":
            raise serializers.ValidationError("Assigned owner must be a mentor (Eagle).")
        return eagle

    def to_internal_value(self, data):
        validated = super().to_internal_value(data)
        # Swap eagle_id (now a User instance) into the `eagle` key the service expects.
        validated["eagle"] = validated.pop("eagle_id")
        return validated

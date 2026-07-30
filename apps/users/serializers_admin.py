"""Serializers for the admin-role management endpoints (plan 18-01)."""

from rest_framework import serializers

from .models_admin import AdminInvite, AdminRoleAudit, AdminRoleRequest


class _UserSummarySerializer(serializers.Serializer):
    """Minimal user fields the admin queue + team page need."""
    id = serializers.UUIDField(read_only=True)
    email = serializers.EmailField(read_only=True)
    full_name = serializers.CharField(read_only=True)
    role = serializers.CharField(read_only=True)
    is_platform_staff = serializers.BooleanField(read_only=True)
    avatar = serializers.SerializerMethodField()

    def get_avatar(self, obj):
        """Delegate to User.avatar_url (Phase 32-01) — the single fallback impl.

        Previously re-derived avatar → profile_picture_url here, which also missed
        the KYC rung, so admin lists showed initials for users whose only picture
        was their verification photo.
        """
        return obj.avatar_url


class AdminRoleRequestSerializer(serializers.ModelSerializer):
    user = _UserSummarySerializer(read_only=True)
    decided_by = _UserSummarySerializer(read_only=True)

    class Meta:
        model = AdminRoleRequest
        fields = [
            "id", "user", "reason", "status",
            "decided_by", "decided_at", "decision_note",
            "created_at", "updated_at",
        ]
        read_only_fields = fields


class SubmitEOISerializer(serializers.Serializer):
    reason = serializers.CharField(min_length=50, max_length=2000)


class DecisionNoteSerializer(serializers.Serializer):
    note = serializers.CharField(required=False, allow_blank=True, max_length=1000)


class RejectNoteSerializer(serializers.Serializer):
    note = serializers.CharField(min_length=10, max_length=1000)


class AdminInviteSerializer(serializers.ModelSerializer):
    invited_by = _UserSummarySerializer(read_only=True)
    accepted_by = _UserSummarySerializer(read_only=True)

    class Meta:
        model = AdminInvite
        # NB: `token` / `token_hash` are deliberately omitted. The raw
        # token is shown ONCE in the POST /invites/ response and never
        # again — DB only has the SHA-256 hash. This prevents an admin
        # browsing past invites from resurrecting an in-flight grant.
        fields = [
            "id", "email", "invited_by", "status",
            "expires_at", "accepted_by", "accepted_at", "message",
            "created_at",
        ]
        read_only_fields = fields


class SendInviteSerializer(serializers.Serializer):
    email = serializers.EmailField()
    message = serializers.CharField(required=False, allow_blank=True, max_length=500)


class RevokeAdminSerializer(serializers.Serializer):
    reason = serializers.CharField(min_length=10, max_length=2000)


class TransferSuperadminSerializer(serializers.Serializer):
    successor_id = serializers.UUIDField()
    reason = serializers.CharField(required=False, allow_blank=True, max_length=2000)


class AdminRoleAuditSerializer(serializers.ModelSerializer):
    actor = _UserSummarySerializer(read_only=True)
    target = _UserSummarySerializer(read_only=True)

    class Meta:
        model = AdminRoleAudit
        fields = [
            "id", "actor", "target", "action", "source",
            "reason", "created_at",
        ]
        read_only_fields = fields


class EligibilitySerializer(serializers.Serializer):
    eligible = serializers.BooleanField()
    reasons = serializers.ListField(child=serializers.CharField())


class TeamMemberSerializer(serializers.Serializer):
    """Stacked or pure admin entry on the /team/ list."""
    id = serializers.UUIDField()
    email = serializers.EmailField()
    full_name = serializers.CharField()
    role = serializers.CharField()
    is_platform_staff = serializers.BooleanField()
    is_superuser = serializers.BooleanField()
    is_stacked = serializers.BooleanField()
    promoted_at = serializers.DateTimeField(allow_null=True)
    promoted_source = serializers.CharField(allow_null=True)
    avatar = serializers.URLField(allow_null=True, required=False)

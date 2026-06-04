"""Serializers for the mentor-application workflow (plan 16-01)."""

from rest_framework import serializers

from .models_mentor_app import MentorApplication, MentorApplicationAudit


class MentorApplicationAuditSerializer(serializers.ModelSerializer):
    # actor is SET_NULL — system-driven events have no actor. allow_null lets
    # DRF render the field as None instead of attempting to stringify the
    # default through CharField.to_representation.
    actor_name = serializers.CharField(
        source="actor.full_name", read_only=True, allow_null=True, default=None
    )

    class Meta:
        model = MentorApplicationAudit
        fields = ["id", "action", "reason", "actor_name", "created_at"]
        read_only_fields = fields


class MentorApplicationSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)
    user_full_name = serializers.CharField(source="user.full_name", read_only=True)
    # reviewed_by is SET_NULL (and is None for any not-yet-decided application).
    reviewed_by_name = serializers.CharField(
        source="reviewed_by.full_name", read_only=True, allow_null=True, default=None,
    )

    class Meta:
        model = MentorApplication
        fields = [
            "id", "status",
            "user_email", "user_full_name",
            "mentor_kyc",
            "submitted_at", "reviewed_at", "reviewed_by_name",
            "rejection_reason", "review_notes",
            "created_at", "updated_at",
        ]
        read_only_fields = fields

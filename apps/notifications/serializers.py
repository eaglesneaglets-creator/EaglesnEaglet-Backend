"""
Notification Serializers
"""

from rest_framework import serializers

from .models import Notification


class NotificationSerializer(serializers.ModelSerializer):
    """Read-only notification serializer."""

    class Meta:
        model = Notification
        fields = [
            "id", "notification_type", "title", "message",
            "is_read", "action_url", "created_at",
        ]
        read_only_fields = fields

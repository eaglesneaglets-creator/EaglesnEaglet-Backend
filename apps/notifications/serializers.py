"""
Notification Serializers
"""

from rest_framework import serializers

from .models import Notification, NotificationPreference
from .registry import ALWAYS_ON, DEFAULTS, DOMAINS, EVENT_LABELS


class NotificationSerializer(serializers.ModelSerializer):
    """Read-only notification serializer."""

    class Meta:
        model = Notification
        fields = [
            "id", "notification_type", "title", "message",
            "is_read", "action_url", "created_at",
        ]
        read_only_fields = fields


class NotificationPreferenceItemSerializer(serializers.Serializer):
    """Single preference row used by PATCH bulk update payload."""

    event_type = serializers.CharField(max_length=30)
    email_enabled = serializers.BooleanField()
    inapp_enabled = serializers.BooleanField()

    def validate_event_type(self, value):
        if value in ALWAYS_ON:
            raise serializers.ValidationError(
                f"Event '{value}' is system-required and cannot be disabled."
            )
        if value not in DEFAULTS:
            raise serializers.ValidationError(f"Unknown event type: {value}")
        return value


class NotificationPreferenceUpdateSerializer(serializers.Serializer):
    """PATCH body wrapper."""

    preferences = NotificationPreferenceItemSerializer(many=True, allow_empty=False)


def build_preferences_response(user):
    """Compose registry-merged preferences grouped by domain."""
    rows = {
        p.event_type: p
        for p in NotificationPreference.objects.filter(user=user)
    }

    domains_out = []
    for key, d in DOMAINS.items():
        events_out = []
        for evt in d["events"]:
            evt_value = evt.value
            pref = rows.get(evt_value)
            if pref is None:
                default_email, default_inapp = DEFAULTS.get(evt_value, (True, True))
                email_on, inapp_on = default_email, default_inapp
            else:
                email_on, inapp_on = pref.email_enabled, pref.inapp_enabled
            events_out.append({
                "event_type": evt_value,
                "label": EVENT_LABELS.get(evt, evt_value),
                "email_enabled": email_on,
                "inapp_enabled": inapp_on,
            })
        domains_out.append({
            "key": key,
            "label": d["label"],
            "events": events_out,
        })

    return {"domains": domains_out}

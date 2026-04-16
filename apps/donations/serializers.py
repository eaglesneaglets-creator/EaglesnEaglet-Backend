"""
Donations Serializers

Input validation and output formatting for the donations API.
"""

import re
from decimal import Decimal

from rest_framework import serializers

from .models import Campaign, Donation, RecurringDonation


class CampaignListSerializer(serializers.ModelSerializer):
    """Compact serializer for campaign grid/list views."""

    progress_percent = serializers.SerializerMethodField()
    created_by_name = serializers.SerializerMethodField()
    donation_count = serializers.SerializerMethodField()

    class Meta:
        model = Campaign
        fields = [
            "id",
            "title",
            "slug",
            "goal_amount",
            "current_amount",
            "currency",
            "progress_percent",
            "status",
            "is_active",
            "image_url",
            "start_date",
            "end_date",
            "created_by_name",
            "donation_count",
            "created_at",
        ]

    def get_progress_percent(self, obj: Campaign) -> float:
        return obj.progress_percent

    def get_created_by_name(self, obj: Campaign) -> str:
        return obj.created_by.full_name or obj.created_by.email

    def get_donation_count(self, obj: Campaign) -> int:
        return obj.donations.filter(status=Donation.Status.SUCCESS).count()


class RecentDonorSerializer(serializers.ModelSerializer):
    """Compact donor entry for the recent donors list."""

    display_name = serializers.SerializerMethodField()

    class Meta:
        model = Donation
        fields = ["display_name", "amount", "currency", "message", "created_at"]

    def get_display_name(self, obj: Donation) -> str:
        if obj.is_anonymous:
            return "Anonymous"
        return obj.donor_name


class CampaignDetailSerializer(serializers.ModelSerializer):
    """Full campaign detail including recent donors."""

    progress_percent = serializers.SerializerMethodField()
    created_by_name = serializers.SerializerMethodField()
    recent_donors = serializers.SerializerMethodField()
    donation_count = serializers.SerializerMethodField()

    class Meta:
        model = Campaign
        fields = [
            "id",
            "title",
            "slug",
            "description",
            "goal_amount",
            "current_amount",
            "currency",
            "progress_percent",
            "status",
            "is_active",
            "image_url",
            "start_date",
            "end_date",
            "created_by_name",
            "recent_donors",
            "donation_count",
            "created_at",
        ]

    def get_progress_percent(self, obj: Campaign) -> float:
        return obj.progress_percent

    def get_created_by_name(self, obj: Campaign) -> str:
        return obj.created_by.full_name or obj.created_by.email

    def get_recent_donors(self, obj: Campaign):
        recent = obj.donations.filter(
            status=Donation.Status.SUCCESS
        ).order_by("-created_at")[:5]
        return RecentDonorSerializer(recent, many=True).data

    def get_donation_count(self, obj: Campaign) -> int:
        return obj.donations.filter(status=Donation.Status.SUCCESS).count()


class CampaignCreateSerializer(serializers.Serializer):
    """Write-only input for creating/updating a campaign."""

    title = serializers.CharField(max_length=200)
    description = serializers.CharField(required=False, default="", allow_blank=True)
    goal_amount = serializers.DecimalField(
        max_digits=12, decimal_places=2, min_value=Decimal("1.00")
    )
    image_url = serializers.URLField(required=False, allow_blank=True, default="")
    start_date = serializers.DateField(required=False, allow_null=True)
    end_date = serializers.DateField(required=False, allow_null=True)


class InitiateDonationSerializer(serializers.Serializer):
    """Write-only input for initiating a Hubtel mobile money donation."""

    campaign_id = serializers.UUIDField()
    amount = serializers.DecimalField(
        max_digits=10,
        decimal_places=2,
        min_value=Decimal("1.00"),
    )
    phone_number = serializers.CharField(max_length=20)
    donor_name = serializers.CharField(max_length=100)
    frequency = serializers.ChoiceField(
        choices=Donation.Frequency.choices,
        default=Donation.Frequency.ONCE,
    )
    is_anonymous = serializers.BooleanField(default=False)
    message = serializers.CharField(
        max_length=500, required=False, default="", allow_blank=True
    )

    def validate_phone_number(self, value: str) -> str:
        """Accept 024XXXXXXX or 233XXXXXXXXX formats."""
        digits = re.sub(r"[\s\-]", "", value)
        if not re.match(r"^(0\d{9}|233\d{9}|\+233\d{9})$", digits):
            raise serializers.ValidationError(
                "Enter a valid Ghana phone number (e.g. 0244123456 or 233244123456)."
            )
        return digits


class DonationSerializer(serializers.ModelSerializer):
    """Read-only output for admin and status checks."""

    campaign_title = serializers.CharField(source="campaign.title", read_only=True)
    campaign_id = serializers.UUIDField(source="campaign.id", read_only=True)

    class Meta:
        model = Donation
        fields = [
            "id",
            "campaign_id",
            "campaign_title",
            "donor_name",
            "amount",
            "currency",
            "phone_number",
            "channel",
            "status",
            "frequency",
            "is_anonymous",
            "message",
            "hubtel_reference",
            "created_at",
        ]


class DonationHistorySerializer(serializers.ModelSerializer):
    """Compact history entry for the authenticated user's donation list."""

    campaign_title = serializers.CharField(source="campaign.title", read_only=True)
    campaign_slug = serializers.CharField(source="campaign.slug", read_only=True)

    class Meta:
        model = Donation
        fields = [
            "id",
            "campaign_title",
            "campaign_slug",
            "amount",
            "currency",
            "status",
            "frequency",
            "is_anonymous",
            "created_at",
        ]


class AdminDonationStatsSerializer(serializers.Serializer):
    """Read-only stats for the admin analytics dashboard."""

    total_raised = serializers.DecimalField(max_digits=14, decimal_places=2)
    monthly_raised = serializers.DecimalField(max_digits=14, decimal_places=2)
    total_donations = serializers.IntegerField()
    active_campaigns = serializers.IntegerField()
    success_rate = serializers.FloatField()
    recent_donations = DonationSerializer(many=True)

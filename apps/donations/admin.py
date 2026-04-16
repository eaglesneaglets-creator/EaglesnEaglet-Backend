"""
Donations Admin

Django admin configuration for campaigns and donations.
"""

from django.contrib import admin

from .models import Campaign, Donation, RecurringDonation


@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = [
        "title",
        "goal_amount",
        "current_amount",
        "progress_display",
        "status",
        "is_active",
        "created_by",
        "created_at",
    ]
    list_filter = ["status", "is_active", "currency"]
    search_fields = ["title", "description", "created_by__email"]
    prepopulated_fields = {"slug": ("title",)}
    readonly_fields = ["current_amount", "created_at", "updated_at"]
    ordering = ["-created_at"]

    @admin.display(description="Progress %")
    def progress_display(self, obj: Campaign) -> str:
        return f"{obj.progress_percent}%"


@admin.register(Donation)
class DonationAdmin(admin.ModelAdmin):
    list_display = [
        "donor_name",
        "campaign",
        "amount",
        "currency",
        "channel",
        "status",
        "frequency",
        "is_anonymous",
        "created_at",
    ]
    list_filter = ["status", "frequency", "channel", "is_anonymous", "campaign"]
    search_fields = [
        "donor_name",
        "phone_number",
        "hubtel_reference",
        "campaign__title",
    ]
    readonly_fields = [
        "hubtel_reference",
        "hubtel_session_id",
        "hubtel_order_id",
        "created_at",
        "updated_at",
    ]
    ordering = ["-created_at"]


@admin.register(RecurringDonation)
class RecurringDonationAdmin(admin.ModelAdmin):
    list_display = [
        "donation",
        "frequency",
        "next_payment_date",
        "is_active",
        "failure_count",
    ]
    list_filter = ["frequency", "is_active"]
    readonly_fields = ["hubtel_recurring_invoice_id", "created_at", "updated_at"]

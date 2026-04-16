"""
Donations Models

Campaign management and Hubtel mobile money donation tracking.
"""

import uuid

from django.db import models
from django.utils.text import slugify

from core.mixins.timestamp import TimestampMixin


class Campaign(TimestampMixin, models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        COMPLETED = "completed", "Completed"
        CANCELLED = "cancelled", "Cancelled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True)
    description = models.TextField(blank=True, default="")
    goal_amount = models.DecimalField(max_digits=12, decimal_places=2)
    current_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    currency = models.CharField(max_length=3, default="GHS")
    is_active = models.BooleanField(default=True)
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.ACTIVE
    )
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.PROTECT,
        related_name="campaigns",
    )
    image_url = models.URLField(blank=True, default="")

    class Meta:
        db_table = "campaigns"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["is_active", "status"]),
        ]

    def __str__(self) -> str:
        return self.title

    def save(self, *args, **kwargs) -> None:
        if not self.slug:
            base_slug = slugify(self.title)
            slug = base_slug
            counter = 1
            while Campaign.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)

    @property
    def progress_percent(self) -> float:
        if not self.goal_amount:
            return 0
        return round(float(self.current_amount / self.goal_amount * 100), 1)


class Donation(TimestampMixin, models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    class Frequency(models.TextChoices):
        ONCE = "once", "One-time"
        WEEKLY = "weekly", "Weekly"
        MONTHLY = "monthly", "Monthly"
        ANNUALLY = "annually", "Annually"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey(
        Campaign,
        on_delete=models.CASCADE,
        related_name="donations",
    )
    donor = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="donations",
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default="GHS")
    phone_number = models.CharField(max_length=20)
    donor_name = models.CharField(max_length=100)
    channel = models.CharField(max_length=20, blank=True, default='')  # auto-detected by Hubtel v2
    hubtel_reference = models.CharField(max_length=100, unique=True, db_index=True)
    hubtel_session_id = models.CharField(max_length=100, blank=True, default="")
    hubtel_order_id = models.CharField(max_length=100, blank=True, default="")
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING
    )
    frequency = models.CharField(
        max_length=20, choices=Frequency.choices, default=Frequency.ONCE
    )
    is_anonymous = models.BooleanField(default=False)
    message = models.TextField(blank=True, default="")

    class Meta:
        db_table = "donations"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["campaign", "status"]),
            models.Index(fields=["donor"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self) -> str:
        return f"{self.donor_name} → {self.campaign.title} ({self.amount} {self.currency})"


class RecurringDonation(TimestampMixin, models.Model):
    class Frequency(models.TextChoices):
        WEEKLY = "weekly", "Weekly"
        MONTHLY = "monthly", "Monthly"
        ANNUALLY = "annually", "Annually"

    donation = models.OneToOneField(
        Donation,
        on_delete=models.CASCADE,
        related_name="recurring",
    )
    hubtel_recurring_invoice_id = models.CharField(max_length=100, blank=True, default="")
    frequency = models.CharField(max_length=20, choices=Frequency.choices)
    next_payment_date = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    failure_count = models.IntegerField(default=0)

    class Meta:
        db_table = "recurring_donations"

    def __str__(self) -> str:
        return f"Recurring {self.frequency} — {self.donation}"

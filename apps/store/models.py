"""
Store Models

Product catalog, shopping cart, and order management.
"""

import uuid
from decimal import Decimal

from django.db import models
from django.utils.text import slugify

from core.mixins.timestamp import TimestampMixin


class Category(TimestampMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=120, unique=True)
    description = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "categories"
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)


class Product(TimestampMixin, models.Model):
    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        PUBLISHED = "published", "Published"
        ARCHIVED = "archived", "Archived"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True)
    description = models.TextField(blank=True, default="")
    category = models.ForeignKey(
        Category, on_delete=models.PROTECT, null=True, blank=True,
        related_name="products"
    )
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock_quantity = models.PositiveIntegerField(default=0)
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.DRAFT
    )
    created_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="created_products"
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
            base = self.slug
            n = 1
            while Product.objects.filter(slug=self.slug).exclude(pk=self.pk).exists():
                self.slug = f"{base}-{n}"
                n += 1
        super().save(*args, **kwargs)


class ProductImage(TimestampMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name="images"
    )
    image_url = models.URLField(max_length=500)
    is_primary = models.BooleanField(default=False)
    display_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["display_order", "-is_primary"]

    def __str__(self):
        return f"Image for {self.product.name}"


class Cart(TimestampMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        "users.User", on_delete=models.CASCADE, related_name="cart"
    )

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"Cart for {self.user.email}"


class CartItem(TimestampMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="cart_items")
    quantity = models.PositiveIntegerField(default=1)

    class Meta:
        unique_together = ("cart", "product")

    def __str__(self):
        return f"{self.quantity}\u00d7 {self.product.name}"


class Order(TimestampMixin, models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PAYMENT_PENDING = "payment_pending", "Payment Pending"
        PAID = "paid", "Paid"
        PROCESSING = "processing", "Processing"
        SHIPPED = "shipped", "Shipped"
        DELIVERED = "delivered", "Delivered"
        CANCELLED = "cancelled", "Cancelled"
        REFUNDED = "refunded", "Refunded"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "users.User", on_delete=models.CASCADE, related_name="orders",
        null=True, blank=True,
    )
    guest_email = models.EmailField(null=True, blank=True)
    guest_name = models.CharField(max_length=200, null=True, blank=True)
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING
    )
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal("0.00"))
    paystack_reference = models.CharField(max_length=100, unique=True, null=True, blank=True)
    paystack_transaction_id = models.CharField(max_length=100, null=True, blank=True)
    receipt_url = models.URLField(null=True, blank=True)
    shipping_address = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        customer = self.user.email if self.user_id else (self.guest_email or "guest")
        return f"Order {self.id} — {customer} ({self.status})"


class OrderItem(TimestampMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(
        Product, on_delete=models.PROTECT, related_name="order_items"
    )
    quantity = models.PositiveIntegerField()
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)  # price snapshot

    class Meta:
        ordering = ["created_at"]

    @property
    def subtotal(self):
        return self.unit_price * self.quantity

    def __str__(self):
        return f"{self.quantity}\u00d7 {self.product.name} @ {self.unit_price}"


class OrderStatusHistory(TimestampMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="status_history")
    from_status = models.CharField(max_length=20, choices=Order.Status.choices, null=True, blank=True)
    to_status = models.CharField(max_length=20, choices=Order.Status.choices)
    changed_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="order_status_changes"
    )
    note = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Order {self.order_id}: {self.from_status} → {self.to_status}"

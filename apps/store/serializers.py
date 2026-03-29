"""
Store Serializers

Input validation and output formatting for the store API.
"""

from decimal import Decimal
from rest_framework import serializers
from .models import Category, Product, ProductImage, Cart, CartItem, Order, OrderItem, OrderStatusHistory


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ["id", "name", "slug", "description", "is_active"]


class ProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductImage
        fields = ["id", "image_url", "is_primary", "display_order"]


class ProductListSerializer(serializers.ModelSerializer):
    """Compact product for grid view."""
    category_name = serializers.CharField(source="category.name", read_only=True, default=None)
    primary_image = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = [
            "id", "name", "slug", "category_name", "price",
            "stock_quantity", "status", "primary_image", "created_at",
        ]

    def get_primary_image(self, obj):
        img = next((i for i in obj.images.all() if i.is_primary), None)
        if img is None:
            first = list(obj.images.all())
            img = first[0] if first else None
        return img.image_url if img else None


class ProductDetailSerializer(serializers.ModelSerializer):
    """Full product detail including all images."""
    category = CategorySerializer(read_only=True)
    images = ProductImageSerializer(many=True, read_only=True)

    class Meta:
        model = Product
        fields = [
            "id", "name", "slug", "description", "category", "price",
            "stock_quantity", "status", "images", "created_at",
        ]


class ProductCreateSerializer(serializers.Serializer):
    """Used for admin product create/update. Images are uploaded as files via multipart."""
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(required=False, default="", allow_blank=True)
    category_id = serializers.UUIDField(required=False, allow_null=True)
    price = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=Decimal("0.01"))
    stock_quantity = serializers.IntegerField(min_value=0, default=0)
    status = serializers.ChoiceField(choices=Product.Status.choices, default=Product.Status.DRAFT)
    # Legacy: still accept image_url for backward compatibility, but prefer file uploads
    image_url = serializers.URLField(required=False, allow_blank=True)


class CartItemSerializer(serializers.ModelSerializer):
    """Cart item with embedded product info."""
    product_id = serializers.UUIDField(source="product.id", read_only=True)
    product_name = serializers.CharField(source="product.name", read_only=True)
    product_slug = serializers.CharField(source="product.slug", read_only=True)
    unit_price = serializers.DecimalField(
        source="product.price", max_digits=10, decimal_places=2, read_only=True
    )
    subtotal = serializers.SerializerMethodField()
    primary_image = serializers.SerializerMethodField()

    class Meta:
        model = CartItem
        fields = [
            "id", "product_id", "product_name", "product_slug",
            "unit_price", "quantity", "subtotal", "primary_image",
        ]

    def get_subtotal(self, obj):
        return obj.product.price * obj.quantity

    def get_primary_image(self, obj):
        img = next((i for i in obj.product.images.all() if i.is_primary), None)
        return img.image_url if img else None


class CartSerializer(serializers.ModelSerializer):
    """Full cart with items and computed total."""
    items = serializers.SerializerMethodField()
    total = serializers.SerializerMethodField()
    item_count = serializers.SerializerMethodField()

    class Meta:
        model = Cart
        fields = ["id", "items", "total", "item_count", "updated_at"]

    def get_items(self, obj):
        items = getattr(obj, "items_list", obj.items.select_related("product").prefetch_related("product__images").all())
        return CartItemSerializer(items, many=True).data

    def get_total(self, obj):
        items = getattr(obj, "items_list", obj.items.select_related("product").all())
        return sum(item.product.price * item.quantity for item in items)

    def get_item_count(self, obj):
        items = getattr(obj, "items_list", obj.items.all())
        return sum(item.quantity for item in items)


class AddToCartSerializer(serializers.Serializer):
    product_id = serializers.UUIDField()
    quantity = serializers.IntegerField(min_value=1, default=1)


class UpdateCartItemSerializer(serializers.Serializer):
    quantity = serializers.IntegerField(min_value=1)


class OrderItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source="product.name", read_only=True)
    product_slug = serializers.CharField(source="product.slug", read_only=True)
    subtotal = serializers.SerializerMethodField()

    class Meta:
        model = OrderItem
        fields = ["id", "product_name", "product_slug", "quantity", "unit_price", "subtotal"]

    def get_subtotal(self, obj):
        return obj.unit_price * obj.quantity


class OrderListSerializer(serializers.ModelSerializer):
    item_count = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            "id", "status", "total_amount", "item_count",
            "paystack_reference", "created_at",
        ]

    def get_item_count(self, obj):
        return sum(i.quantity for i in obj.items.all())


class OrderDetailSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)

    class Meta:
        model = Order
        fields = [
            "id", "status", "total_amount", "items",
            "paystack_reference", "paystack_transaction_id",
            "receipt_url", "shipping_address", "created_at",
        ]


class CreateOrderSerializer(serializers.Serializer):
    shipping_address = serializers.DictField(required=False, default=dict)


class GuestCartItemSerializer(serializers.Serializer):
    product_id = serializers.UUIDField()
    quantity = serializers.IntegerField(min_value=1)


class GuestCheckoutSerializer(serializers.Serializer):
    guest_email = serializers.EmailField()
    guest_name = serializers.CharField(max_length=200)
    items = GuestCartItemSerializer(many=True)
    shipping_address = serializers.DictField(required=False, default=dict)


# ─── Admin Order Serializers ──────────────────────────────────────────────────

class OrderStatusHistorySerializer(serializers.ModelSerializer):
    changed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = OrderStatusHistory
        fields = ["id", "from_status", "to_status", "changed_by_name", "note", "created_at"]

    def get_changed_by_name(self, obj):
        if obj.changed_by:
            name = f"{obj.changed_by.first_name} {obj.changed_by.last_name}".strip()
            return name or obj.changed_by.email
        return "System"


class AdminOrderListSerializer(serializers.ModelSerializer):
    order_number = serializers.SerializerMethodField()
    customer_name = serializers.SerializerMethodField()
    customer_email = serializers.SerializerMethodField()
    item_count = serializers.SerializerMethodField()
    is_guest = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            "id", "order_number", "customer_name", "customer_email",
            "is_guest", "status", "total_amount", "item_count", "created_at",
        ]

    def get_order_number(self, obj):
        return str(obj.id)[:8].upper()

    def get_customer_name(self, obj):
        if obj.user_id:
            return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.email
        return obj.guest_name or "Guest"

    def get_customer_email(self, obj):
        return obj.user.email if obj.user_id else (obj.guest_email or "")

    def get_item_count(self, obj):
        return sum(i.quantity for i in obj.items.all())

    def get_is_guest(self, obj):
        return obj.user_id is None


class AdminOrderDetailSerializer(serializers.ModelSerializer):
    order_number = serializers.SerializerMethodField()
    customer_name = serializers.SerializerMethodField()
    customer_email = serializers.SerializerMethodField()
    is_guest = serializers.SerializerMethodField()
    items = OrderItemSerializer(many=True, read_only=True)
    status_history = OrderStatusHistorySerializer(many=True, read_only=True)

    class Meta:
        model = Order
        fields = [
            "id", "order_number", "customer_name", "customer_email", "is_guest",
            "status", "total_amount", "items", "shipping_address",
            "paystack_reference", "paystack_transaction_id", "receipt_url",
            "status_history", "created_at",
        ]

    def get_order_number(self, obj):
        return str(obj.id)[:8].upper()

    def get_customer_name(self, obj):
        if obj.user_id:
            return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.email
        return obj.guest_name or "Guest"

    def get_customer_email(self, obj):
        return obj.user.email if obj.user_id else (obj.guest_email or "")

    def get_is_guest(self, obj):
        return obj.user_id is None


# Allowed status transitions — enforced in AdminOrderStatusUpdateSerializer
ORDER_TRANSITIONS: dict = {
    "pending":          ["payment_pending", "cancelled"],
    "payment_pending":  ["paid", "cancelled"],
    "paid":             ["processing", "refunded"],
    "processing":       ["shipped", "cancelled"],
    "shipped":          ["delivered"],
    "delivered":        ["refunded"],
    "cancelled":        [],
    "refunded":         [],
}


class AdminOrderStatusUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Order.Status.choices)
    note = serializers.CharField(required=False, allow_blank=True, default="")

    def validate(self, data):
        order = self.context["order"]
        allowed = ORDER_TRANSITIONS.get(order.status, [])
        if data["status"] not in allowed:
            raise serializers.ValidationError({
                "status": (
                    f"Cannot transition from '{order.status}' to '{data['status']}'. "
                    f"Allowed next statuses: {allowed or ['none']}"
                )
            })
        return data

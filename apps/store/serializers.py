"""
Store Serializers

Input validation and output formatting for the store API.
"""

from decimal import Decimal
from rest_framework import serializers
from .models import Category, Product, ProductImage, Cart, CartItem, Order, OrderItem


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
    """Used for admin product create/update."""
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(required=False, default="", allow_blank=True)
    category_id = serializers.UUIDField(required=False, allow_null=True)
    price = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=Decimal("0.01"))
    stock_quantity = serializers.IntegerField(min_value=0, default=0)
    status = serializers.ChoiceField(choices=Product.Status.choices, default=Product.Status.DRAFT)
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

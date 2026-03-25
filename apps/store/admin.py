"""
Store Admin Configuration
"""
from django.contrib import admin
from .models import Category, Product, ProductImage, Cart, CartItem, Order, OrderItem


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "is_active", "created_at"]
    prepopulated_fields = {"slug": ("name",)}
    list_filter = ["is_active"]


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ["name", "category", "price", "stock_quantity", "status", "created_at"]
    list_filter = ["status", "category"]
    search_fields = ["name", "description"]
    prepopulated_fields = {"slug": ("name",)}


@admin.register(ProductImage)
class ProductImageAdmin(admin.ModelAdmin):
    list_display = ["product", "is_primary", "display_order"]
    list_filter = ["is_primary"]


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "status", "total_amount", "created_at"]
    list_filter = ["status"]
    search_fields = ["user__email"]
    readonly_fields = ["id", "created_at", "updated_at"]


admin.site.register(Cart)
admin.site.register(CartItem)
admin.site.register(OrderItem)

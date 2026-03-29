"""
Store URL Configuration
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    CategoryViewSet, ProductViewSet, ProductImageUploadView,
    ProductBySlugView,
    CartView, CartItemView, OrderViewSet, GuestCheckoutView, GuestOrderDetailView,
    AdminOrderViewSet,
    InitializePaymentView, VerifyPaymentView, PaystackWebhookView,
)

router = DefaultRouter()
router.register(r"categories", CategoryViewSet, basename="category")
router.register(r"products", ProductViewSet, basename="product")
router.register(r"orders", OrderViewSet, basename="order")
router.register(r"admin/orders", AdminOrderViewSet, basename="admin-order")

urlpatterns = [
    path("", include(router.urls)),
    path("products/by-slug/<slug:slug>/", ProductBySlugView.as_view(), name="product-by-slug"),
    path("products/<uuid:product_id>/images/", ProductImageUploadView.as_view(), name="product-images"),
    path("products/<uuid:product_id>/images/<uuid:image_id>/", ProductImageUploadView.as_view(), name="product-image-detail"),
    path("cart/", CartView.as_view(), name="cart"),
    path("cart/items/", CartItemView.as_view(), name="cart-items"),
    path("cart/items/<uuid:pk>/", CartItemView.as_view(), name="cart-item-detail"),
    path("orders/<uuid:pk>/cancel/", OrderViewSet.as_view({"post": "cancel"}), name="order-cancel"),
    path("guest-checkout/", GuestCheckoutView.as_view(), name="guest-checkout"),
    path("guest-orders/<uuid:pk>/", GuestOrderDetailView.as_view(), name="guest-order-detail"),
    path("admin/orders/<uuid:pk>/update-status/", AdminOrderViewSet.as_view({"patch": "update_status"}), name="admin-order-update-status"),
    # MM-20: Payment Gateway
    path("orders/<uuid:pk>/initialize-payment/", InitializePaymentView.as_view(), name="order-initialize-payment"),
    path("orders/<uuid:pk>/verify/", VerifyPaymentView.as_view(), name="order-verify"),
    path("webhook/paystack/", PaystackWebhookView.as_view(), name="paystack-webhook"),
]

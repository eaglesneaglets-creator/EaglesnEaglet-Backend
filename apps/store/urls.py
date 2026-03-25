"""
Store URL Configuration
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import CategoryViewSet, ProductViewSet, CartView, CartItemView, OrderViewSet

router = DefaultRouter()
router.register(r"categories", CategoryViewSet, basename="category")
router.register(r"products", ProductViewSet, basename="product")
router.register(r"orders", OrderViewSet, basename="order")

urlpatterns = [
    path("", include(router.urls)),
    path("cart/", CartView.as_view(), name="cart"),
    path("cart/items/", CartItemView.as_view(), name="cart-items"),
    path("cart/items/<uuid:pk>/", CartItemView.as_view(), name="cart-item-detail"),
    path("orders/<uuid:pk>/cancel/", OrderViewSet.as_view({"post": "cancel"}), name="order-cancel"),
]

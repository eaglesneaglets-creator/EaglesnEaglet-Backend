"""
Store Views

Product catalog (public read, admin write), cart management, and order lifecycle.
"""

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from core.permissions import IsAdmin

from .serializers import (
    CategorySerializer,
    ProductListSerializer,
    ProductDetailSerializer,
    ProductCreateSerializer,
    CartSerializer,
    CartItemSerializer,
    AddToCartSerializer,
    UpdateCartItemSerializer,
    OrderListSerializer,
    OrderDetailSerializer,
    CreateOrderSerializer,
)
from .services import StoreService
from .models import Product as ProductModel


def success(data, status_code=status.HTTP_200_OK, meta=None):
    body = {"success": True, "data": data}
    if meta:
        body["meta"] = meta
    return Response(body, status=status_code)


class CategoryViewSet(ViewSet):
    """
    GET /store/categories/        — list active categories (public)
    POST /store/categories/       — create category (admin only)
    """

    def get_permissions(self):
        if self.action == "create":
            return [IsAuthenticated(), IsAdmin()]
        return [AllowAny()]

    def list(self, request):
        categories = StoreService.list_active_categories()
        return success(CategorySerializer(categories, many=True).data)

    def create(self, request):
        serializer = CategorySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category = StoreService.create_category(request.user, serializer.validated_data)
        return success(CategorySerializer(category).data, status.HTTP_201_CREATED)


class ProductViewSet(ViewSet):
    """
    GET    /store/products/        — list published (public); all statuses for admin
    POST   /store/products/        — create product (admin only)
    GET    /store/products/<id>/   — product detail (public)
    PATCH  /store/products/<id>/   — update product (admin only)
    DELETE /store/products/<id>/   — archive product (admin only)
    """

    def get_permissions(self):
        if self.action in ("create", "partial_update", "destroy"):
            return [IsAuthenticated(), IsAdmin()]
        return [AllowAny()]

    def list(self, request):
        category_slug = request.query_params.get("category")
        search = request.query_params.get("search")
        if request.user.is_authenticated and getattr(request.user, "role", None) == "admin":
            qs = ProductModel.objects.filter(
                status__in=[ProductModel.Status.PUBLISHED, ProductModel.Status.DRAFT]
            ).select_related("category").prefetch_related("images")
            if category_slug:
                qs = qs.filter(category__slug=category_slug)
            if search:
                qs = qs.filter(name__icontains=search)
        else:
            qs = StoreService.get_published_products(category_slug, search).prefetch_related("images")
        return success(ProductListSerializer(qs, many=True).data)

    def create(self, request):
        serializer = ProductCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        product = StoreService.create_product(request.user, serializer.validated_data)
        return success(ProductDetailSerializer(product).data, status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        product = StoreService.get_product_by_id(pk)
        return success(ProductDetailSerializer(product).data)

    def partial_update(self, request, pk=None):
        serializer = ProductCreateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        product = StoreService.update_product(request.user, pk, serializer.validated_data)
        return success(ProductDetailSerializer(product).data)

    def destroy(self, request, pk=None):
        StoreService.delete_product(request.user, pk)
        return Response({"success": True}, status=status.HTTP_200_OK)


class CartView(APIView):
    """GET /store/cart/ — get current user's cart"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cart = StoreService.get_cart_with_items(request.user)
        return success(CartSerializer(cart).data)


class CartItemView(APIView):
    """
    POST   /store/cart/items/       — add item to cart
    PATCH  /store/cart/items/<pk>/  — update item quantity
    DELETE /store/cart/items/<pk>/  — remove item from cart
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = AddToCartSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data
        item = StoreService.add_to_cart(request.user, str(d["product_id"]), d["quantity"])
        return success(CartItemSerializer(item).data, status.HTTP_201_CREATED)

    def patch(self, request, pk=None):
        serializer = UpdateCartItemSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        item = StoreService.update_cart_item(request.user, pk, serializer.validated_data["quantity"])
        return success(CartItemSerializer(item).data)

    def delete(self, request, pk=None):
        StoreService.remove_from_cart(request.user, pk)
        return Response({"success": True}, status=status.HTTP_200_OK)


class OrderViewSet(ViewSet):
    """
    GET  /store/orders/              — user's order history
    POST /store/orders/              — create order from cart
    GET  /store/orders/<id>/         — order detail
    POST /store/orders/<id>/cancel/  — cancel pending order
    """
    permission_classes = [IsAuthenticated]

    def list(self, request):
        orders = StoreService.get_user_orders(request.user)
        return success(OrderListSerializer(orders, many=True).data)

    def create(self, request):
        serializer = CreateOrderSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        order = StoreService.create_order_from_cart(
            request.user,
            shipping_address=serializer.validated_data.get("shipping_address", {}),
        )
        return success(OrderDetailSerializer(order).data, status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        order = StoreService.get_order_detail(request.user, pk)
        return success(OrderDetailSerializer(order).data)

    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        order = StoreService.cancel_order(request.user, pk)
        return success(OrderDetailSerializer(order).data)

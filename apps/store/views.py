"""
Store Views

Product catalog (public read, admin write), cart management, and order lifecycle.
"""

import json
import logging

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, JSONParser, FormParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from core.permissions import IsAdmin

logger = logging.getLogger(__name__)

from .serializers import (
    CategorySerializer,
    ProductListSerializer,
    ProductDetailSerializer,
    ProductCreateSerializer,
    ProductImageSerializer,
    CartSerializer,
    CartItemSerializer,
    AddToCartSerializer,
    UpdateCartItemSerializer,
    OrderListSerializer,
    OrderDetailSerializer,
    CreateOrderSerializer,
    GuestCheckoutSerializer,
    AdminOrderListSerializer,
    AdminOrderDetailSerializer,
    AdminOrderStatusUpdateSerializer,
)
from .services import StoreService
from .models import Product as ProductModel, Order, OrderStatusHistory


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
    POST   /store/products/        — create product (admin only, accepts multipart with images)
    GET    /store/products/<id>/   — product detail (public)
    PATCH  /store/products/<id>/   — update product (admin only, accepts multipart with images)
    DELETE /store/products/<id>/   — archive product (admin only)
    """
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_permissions(self):
        if self.action in ("create", "partial_update", "destroy"):
            return [IsAuthenticated(), IsAdmin()]
        return [AllowAny()]

    def list(self, request):
        category_slug = request.query_params.get("category")
        search = request.query_params.get("search")
        is_admin = request.user.is_authenticated and (
            request.user.is_staff or request.user.is_superuser
            or getattr(request.user, "role", None) == "admin"
        )
        if is_admin:
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
        # Handle file uploads (images field from multipart form)
        images = request.FILES.getlist("images")
        if images:
            StoreService.upload_product_images(request.user, str(product.id), images)
            product.refresh_from_db()
        return success(ProductDetailSerializer(product).data, status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        product = StoreService.get_product_by_id(pk)
        return success(ProductDetailSerializer(product).data)

    def partial_update(self, request, pk=None):
        serializer = ProductCreateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        product = StoreService.update_product(request.user, pk, serializer.validated_data)
        # Handle file uploads on update too
        images = request.FILES.getlist("images")
        if images:
            StoreService.upload_product_images(request.user, str(product.id), images)
            product.refresh_from_db()
        return success(ProductDetailSerializer(product).data)

    def destroy(self, request, pk=None):
        StoreService.delete_product(request.user, pk)
        return Response({"success": True}, status=status.HTTP_200_OK)


class ProductImageUploadView(APIView):
    """
    POST /store/products/<product_id>/images/  — upload images to an existing product
    DELETE /store/products/<product_id>/images/<image_id>/  — remove a product image
    """
    permission_classes = [IsAuthenticated, IsAdmin]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, product_id=None):
        images = request.FILES.getlist("images")
        if not images:
            return Response(
                {"success": False, "error": {"message": "No images provided."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        created = StoreService.upload_product_images(request.user, str(product_id), images)
        return success(
            ProductImageSerializer(created, many=True).data,
            status.HTTP_201_CREATED,
        )

    def delete(self, request, product_id=None, image_id=None):
        from .models import ProductImage
        deleted, _ = ProductImage.objects.filter(
            pk=image_id, product_id=product_id
        ).delete()
        if not deleted:
            return Response(
                {"success": False, "error": {"message": "Image not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({"success": True}, status=status.HTTP_200_OK)


class ProductBySlugView(APIView):
    """
    GET /store/products/by-slug/<slug>/  — retrieve a single published product by slug (public)
    """
    permission_classes = [AllowAny]

    def get(self, request, slug=None):
        product = StoreService.get_product_by_slug(slug)
        return success(ProductDetailSerializer(product).data)


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


class GuestCheckoutView(APIView):
    """
    POST /store/guest-checkout/
    Create an order for a guest without requiring authentication.
    Accepts: guest_email, guest_name, items [{product_id, quantity}], shipping_address
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = GuestCheckoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data
        order = StoreService.create_guest_order(
            guest_email=d["guest_email"],
            guest_name=d["guest_name"],
            items_data=[
                {"product_id": str(item["product_id"]), "quantity": item["quantity"]}
                for item in d["items"]
            ],
            shipping_address=d.get("shipping_address", {}),
        )
        return success(OrderDetailSerializer(order).data, status.HTTP_201_CREATED)


class GuestOrderDetailView(APIView):
    """
    GET /store/guest-orders/<pk>/
    Public order detail lookup for guest orders — no authentication required.
    Only returns orders that have no user (guest orders).
    """
    permission_classes = [AllowAny]

    def get(self, request, pk=None):
        from rest_framework.exceptions import NotFound
        try:
            order = Order.objects.prefetch_related(
                "items", "items__product", "items__product__images"
            ).get(pk=pk, user__isnull=True)
        except Order.DoesNotExist:
            raise NotFound("Order not found.")
        return success(OrderDetailSerializer(order).data)


class AdminOrderViewSet(ViewSet):
    """
    GET   /store/admin/orders/                     — paginated list (admin only)
    GET   /store/admin/orders/<id>/                — full detail with status history
    PATCH /store/admin/orders/<id>/update-status/  — transition status, optionally with a note
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def list(self, request):
        from django.db.models import Q
        from django.core.paginator import Paginator

        qs = (
            Order.objects
            .prefetch_related("items", "status_history")
            .select_related("user")
            .order_by("-created_at")
        )

        status_filter = request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)

        date_from = request.query_params.get("date_from")
        if date_from:
            qs = qs.filter(created_at__date__gte=date_from)

        date_to = request.query_params.get("date_to")
        if date_to:
            qs = qs.filter(created_at__date__lte=date_to)

        search = request.query_params.get("search")
        if search:
            qs = qs.filter(
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(user__email__icontains=search) |
                Q(guest_name__icontains=search) |
                Q(guest_email__icontains=search)
            )

        page_size = min(int(request.query_params.get("page_size", 20)), 100)
        page_num = max(int(request.query_params.get("page", 1)), 1)
        paginator = Paginator(qs, page_size)
        page = paginator.get_page(page_num)

        return success(
            AdminOrderListSerializer(page.object_list, many=True).data,
            meta={
                "total": paginator.count,
                "page": page_num,
                "page_size": page_size,
                "pages": paginator.num_pages,
            },
        )

    def retrieve(self, request, pk=None):
        from rest_framework.exceptions import NotFound
        try:
            order = (
                Order.objects
                .prefetch_related(
                    "items", "items__product",
                    "status_history", "status_history__changed_by",
                )
                .select_related("user")
                .get(pk=pk)
            )
        except Order.DoesNotExist:
            raise NotFound("Order not found.")
        return success(AdminOrderDetailSerializer(order).data)

    @action(detail=True, methods=["patch"], url_path="update-status")
    def update_status(self, request, pk=None):
        from rest_framework.exceptions import NotFound
        try:
            order = Order.objects.select_related("user").get(pk=pk)
        except Order.DoesNotExist:
            raise NotFound("Order not found.")

        serializer = AdminOrderStatusUpdateSerializer(
            data=request.data, context={"order": order}
        )
        serializer.is_valid(raise_exception=True)

        old_status = order.status
        new_status = serializer.validated_data["status"]
        note = serializer.validated_data.get("note", "")

        order.status = new_status
        order.save(update_fields=["status", "updated_at"])

        OrderStatusHistory.objects.create(
            order=order,
            from_status=old_status,
            to_status=new_status,
            changed_by=request.user,
            note=note,
        )

        # Fire shipped email to customer
        if new_status == Order.Status.SHIPPED:
            from apps.notifications.tasks import send_email_notification, send_guest_email_notification
            ctx = {
                "order_id": str(order.id),
                "order_short": str(order.id)[:8].upper(),
                "shipping_address": order.shipping_address,
            }
            if order.user_id:
                send_email_notification.delay(
                    str(order.user_id),
                    "Your order is on its way! 🚚",
                    "emails/order_shipped.html",
                    ctx,
                )
            elif order.guest_email:
                send_guest_email_notification.delay(
                    order.guest_email,
                    "Your order is on its way! 🚚",
                    "emails/order_shipped.html",
                    ctx,
                )

        order.refresh_from_db()
        # Re-fetch with full relations for response
        order = (
            Order.objects
            .prefetch_related(
                "items", "items__product",
                "status_history", "status_history__changed_by",
            )
            .select_related("user")
            .get(pk=pk)
        )
        return success(AdminOrderDetailSerializer(order).data)


# =============================================================================
# Payment Views (MM-20)
# =============================================================================

class InitializePaymentView(APIView):
    """
    POST /store/orders/<id>/initialize-payment/

    Initializes a Paystack transaction for the given order.
    Works for both authenticated users AND guests (AllowAny).

    For authenticated users: order must belong to request.user.
    For guests: order must be a guest order (user=None) with matching ID.

    Sets order.paystack_reference = str(order.id) (idempotency key) and
    transitions status to PAYMENT_PENDING before calling Paystack.

    Returns: { success: true, data: { authorization_url, reference } }
    """
    permission_classes = [AllowAny]
    authentication_classes = []  # guests have no JWT — skip auth parse entirely

    def post(self, request, pk=None):
        from rest_framework.exceptions import NotFound as DRFNotFound
        from .payments import PaystackService

        # Fetch order — authenticated users get ownership check, guests get guest order
        try:
            if request.user and request.user.is_authenticated:
                order = StoreService.get_order_detail(request.user, pk)
            else:
                # Guest: only allow access to guest orders (user=None)
                order = Order.objects.prefetch_related(
                    "items", "items__product"
                ).get(pk=pk, user__isnull=True)
        except Order.DoesNotExist:
            raise DRFNotFound("Order not found.")

        if order.status not in (Order.Status.PENDING, Order.Status.PAYMENT_PENDING):
            return Response(
                {"success": False, "error": {"message": f"Order cannot be paid in '{order.status}' status."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Set reference before calling Paystack — ensures idempotency key is
        # persisted even if the Paystack call times out and is retried
        if not order.paystack_reference:
            order.paystack_reference = str(order.id)
            order.status = Order.Status.PAYMENT_PENDING
            order.save(update_fields=["paystack_reference", "status"])

        # Pass user=None for guest orders — PaystackService uses order.guest_email
        user = request.user if (request.user and request.user.is_authenticated) else None
        data = PaystackService.initialize_payment(order, user)
        return success(data)


class VerifyPaymentView(APIView):
    """
    POST /store/orders/<id>/verify/

    Manually verifies an order's payment status against Paystack.
    Called by the frontend when polling after redirect (?verify=1).
    Works for both authenticated and guest orders (AllowAny).

    Returns: updated OrderDetailSerializer data
    """
    permission_classes = [AllowAny]
    authentication_classes = []  # allow unauthenticated access for guest orders

    def post(self, request, pk=None):
        from rest_framework.exceptions import NotFound as DRFNotFound
        from .payments import PaystackService

        # Support both authenticated user orders and guest orders
        try:
            if request.user and request.user.is_authenticated:
                order = StoreService.get_order_detail(request.user, pk)
            else:
                # Guest: only allow access to guest orders (user=None) to prevent IDOR.
                # An unauthenticated caller must not be able to trigger verification
                # or read details for orders belonging to registered users.
                order = Order.objects.prefetch_related(
                    "items", "items__product", "items__product__images"
                ).get(pk=pk, user__isnull=True)
        except Order.DoesNotExist:
            raise DRFNotFound("Order not found.")

        if not order.paystack_reference:
            return Response(
                {"success": False, "error": {"message": "No payment reference found for this order."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = PaystackService.verify_payment(order.paystack_reference)
        pay_status = result.get("status") if isinstance(result, dict) else getattr(result, "status", None)

        if pay_status == "success":
            txn_id = str(result.get("id", "")) if isinstance(result, dict) else str(getattr(result, "id", ""))
            order = StoreService.mark_order_paid(order.paystack_reference, txn_id)

        # Reload with relations for serializer
        order = Order.objects.prefetch_related(
            "items", "items__product", "items__product__images"
        ).get(pk=order.pk)
        return success(OrderDetailSerializer(order).data)


@method_decorator(csrf_exempt, name="dispatch")
class PaystackWebhookView(APIView):
    """
    POST /store/webhook/paystack/

    CSRF-exempt Paystack webhook receiver.

    Security:
    - Validates HMAC-SHA512 signature BEFORE touching any data
    - Returns 400 immediately on invalid signature (no DB access)
    - Returns 200 immediately for all valid requests (prevents Paystack retries)
    - Dispatches Celery task for async processing (keeps response < 500ms)

    The Celery task (process_successful_payment) is idempotent — safe on retries.
    """
    permission_classes = [AllowAny]
    authentication_classes = []  # Paystack server-to-server: no JWT to parse

    def post(self, request):
        from .payments import PaystackService
        from .tasks import process_successful_payment

        signature = request.META.get("HTTP_X_PAYSTACK_SIGNATURE", "")
        payload = request.body  # raw bytes — MUST be read before any parsing

        if not PaystackService.validate_webhook_signature(payload, signature):
            logger.warning("PaystackWebhookView: invalid signature rejected.")
            return Response(
                {"success": False, "error": {"message": "Invalid signature."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        event = data.get("event", "")
        logger.info("Paystack webhook received: event=%s", event)

        if event == "charge.success":
            event_data = data.get("data", {})
            ref = event_data.get("reference", "")
            txn_id = str(event_data.get("id", ""))
            if ref:
                process_successful_payment.delay(ref, txn_id)
                logger.info("Dispatched process_successful_payment for ref=%s", ref)

        # Always return 200 to Paystack — including for unhandled event types.
        # A non-200 response causes Paystack to retry the webhook indefinitely.
        return Response({"status": "ok"}, status=status.HTTP_200_OK)

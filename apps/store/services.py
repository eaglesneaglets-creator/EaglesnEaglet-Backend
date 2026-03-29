"""
Store Services

Business logic for product catalog, cart management, and order lifecycle.
"""

import logging
from decimal import Decimal

from django.db import transaction
from django.db.models import F
from django.utils.text import slugify
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError

from .models import Category, Product, ProductImage, Cart, CartItem, Order, OrderItem

logger = logging.getLogger(__name__)


class StoreService:

    @staticmethod
    def _is_admin(user) -> bool:
        """Check admin status consistently with IsAdmin permission class."""
        if user.is_staff or user.is_superuser:
            return True
        return getattr(user, "role", None) == "admin"

    # ------------------------------------------------------------------
    # Categories
    # ------------------------------------------------------------------

    @staticmethod
    def list_active_categories():
        return Category.objects.filter(is_active=True)

    @staticmethod
    @transaction.atomic
    def create_category(user, data: dict) -> Category:
        if not StoreService._is_admin(user):
            raise PermissionDenied("Only admins can create categories.")
        name = data["name"]
        slug = slugify(name)
        base = slug
        n = 1
        while Category.objects.filter(slug=slug).exists():
            slug = f"{base}-{n}"
            n += 1
        return Category.objects.create(
            name=name,
            slug=slug,
            description=data.get("description", ""),
        )

    # ------------------------------------------------------------------
    # Products
    # ------------------------------------------------------------------

    @staticmethod
    def get_published_products(category_slug: str = None, search: str = None):
        qs = Product.objects.filter(status=Product.Status.PUBLISHED).select_related("category")
        if category_slug:
            qs = qs.filter(category__slug=category_slug)
        if search:
            qs = qs.filter(name__icontains=search)
        return qs

    @staticmethod
    def get_product_by_slug(slug: str) -> Product:
        try:
            return Product.objects.select_related("category").prefetch_related("images").get(
                slug=slug, status=Product.Status.PUBLISHED
            )
        except Product.DoesNotExist:
            raise NotFound(f"Product '{slug}' not found.")

    @staticmethod
    def get_product_by_id(product_id: str) -> Product:
        try:
            return Product.objects.select_related("category").prefetch_related("images").get(pk=product_id)
        except Product.DoesNotExist:
            raise NotFound("Product not found.")

    @staticmethod
    @transaction.atomic
    def create_product(user, data: dict) -> Product:
        if not StoreService._is_admin(user):
            raise PermissionDenied("Only admins can create products.")
        name = data["name"]
        slug = slugify(name)
        base = slug
        n = 1
        while Product.objects.filter(slug=slug).exists():
            slug = f"{base}-{n}"
            n += 1
        product = Product.objects.create(
            name=name,
            slug=slug,
            description=data.get("description", ""),
            category_id=data.get("category_id"),
            price=Decimal(str(data["price"])),
            stock_quantity=data.get("stock_quantity", 0),
            status=data.get("status", Product.Status.DRAFT),
            created_by=user,
        )
        # Handle primary image URL if provided
        image_url = data.get("image_url")
        if image_url:
            ProductImage.objects.create(
                product=product,
                image_url=image_url,
                is_primary=True,
                display_order=0,
            )
        logger.info("Product created: %s by %s", product.name, user.email)
        return product

    @staticmethod
    @transaction.atomic
    def upload_product_images(user, product_id: str, files: list, set_primary: bool = True) -> list:
        """Upload one or more images to Cloudinary and attach them to a product."""
        if not StoreService._is_admin(user):
            raise PermissionDenied("Only admins can upload product images.")
        try:
            product = Product.objects.get(pk=product_id)
        except Product.DoesNotExist:
            raise NotFound("Product not found.")

        from core.storage import upload_to_cloudinary

        created_images = []
        existing_count = product.images.count()

        for i, file in enumerate(files):
            result = upload_to_cloudinary(file, file_type="store_images")
            image_url = result.get("secure_url") or result.get("url")
            is_primary = set_primary and existing_count == 0 and i == 0
            img = ProductImage.objects.create(
                product=product,
                image_url=image_url,
                is_primary=is_primary,
                display_order=existing_count + i,
            )
            created_images.append(img)

        logger.info(
            "Uploaded %d image(s) for product %s by %s",
            len(created_images), product.name, user.email,
        )
        return created_images

    @staticmethod
    @transaction.atomic
    def update_product(user, product_id: str, data: dict) -> Product:
        if not StoreService._is_admin(user):
            raise PermissionDenied("Only admins can update products.")
        try:
            product = Product.objects.get(pk=product_id)
        except Product.DoesNotExist:
            raise NotFound("Product not found.")
        for field in ("name", "description", "stock_quantity", "status"):
            if field in data:
                setattr(product, field, data[field])
        if "category_id" in data:
            product.category_id = data["category_id"]
        if "price" in data:
            product.price = Decimal(str(data["price"]))
        product.save()
        # Update primary image if new URL provided
        image_url = data.get("image_url")
        if image_url:
            ProductImage.objects.filter(product=product, is_primary=True).delete()
            ProductImage.objects.create(
                product=product,
                image_url=image_url,
                is_primary=True,
                display_order=0,
            )
        return product

    @staticmethod
    @transaction.atomic
    def delete_product(user, product_id: str) -> None:
        if not StoreService._is_admin(user):
            raise PermissionDenied("Only admins can delete products.")
        try:
            product = Product.objects.get(pk=product_id)
        except Product.DoesNotExist:
            raise NotFound("Product not found.")
        product.status = Product.Status.ARCHIVED
        product.save(update_fields=["status"])
        logger.info("Product archived: %s by %s", product.name, user.email)

    # ------------------------------------------------------------------
    # Cart
    # ------------------------------------------------------------------

    @staticmethod
    def get_or_create_cart(user) -> Cart:
        cart, _ = Cart.objects.get_or_create(user=user)
        return cart

    @staticmethod
    def get_cart_with_items(user) -> Cart:
        cart = StoreService.get_or_create_cart(user)
        cart.items_list = CartItem.objects.filter(cart=cart).select_related(
            "product", "product__category"
        ).prefetch_related("product__images")
        return cart

    @staticmethod
    @transaction.atomic
    def add_to_cart(user, product_id: str, quantity: int = 1) -> CartItem:
        if quantity < 1:
            raise ValidationError({"quantity": "Quantity must be at least 1."})
        try:
            product = Product.objects.get(pk=product_id, status=Product.Status.PUBLISHED)
        except Product.DoesNotExist:
            raise NotFound("Product not found or not available.")
        if product.stock_quantity < quantity:
            raise ValidationError({"quantity": f"Only {product.stock_quantity} in stock."})
        cart = StoreService.get_or_create_cart(user)
        item, created = CartItem.objects.get_or_create(
            cart=cart,
            product=product,
            defaults={"quantity": quantity},
        )
        if not created:
            new_qty = item.quantity + quantity
            if product.stock_quantity < new_qty:
                raise ValidationError(
                    {"quantity": f"Cannot add {quantity} more — only {product.stock_quantity} in stock."}
                )
            item.quantity = new_qty
            item.save(update_fields=["quantity"])
        return item

    @staticmethod
    @transaction.atomic
    def update_cart_item(user, item_id: str, quantity: int) -> CartItem:
        if quantity < 1:
            raise ValidationError({"quantity": "Quantity must be at least 1."})
        try:
            item = CartItem.objects.select_related("product").get(
                pk=item_id, cart__user=user
            )
        except CartItem.DoesNotExist:
            raise NotFound("Cart item not found.")
        if item.product.stock_quantity < quantity:
            raise ValidationError(
                {"quantity": f"Only {item.product.stock_quantity} in stock."}
            )
        item.quantity = quantity
        item.save(update_fields=["quantity"])
        return item

    @staticmethod
    @transaction.atomic
    def remove_from_cart(user, item_id: str) -> None:
        deleted, _ = CartItem.objects.filter(pk=item_id, cart__user=user).delete()
        if not deleted:
            raise NotFound("Cart item not found.")

    @staticmethod
    @transaction.atomic
    def clear_cart(user) -> None:
        CartItem.objects.filter(cart__user=user).delete()

    # ------------------------------------------------------------------
    # Orders
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def create_order_from_cart(user, shipping_address: dict = None) -> Order:
        """
        Convert the user's cart into a placed Order.

        Uses select_for_update() on products to prevent overselling under
        concurrent checkouts. Snapshots unit_price at creation time.
        Raises ValidationError if cart is empty or any item is out of stock.
        """
        cart = StoreService.get_or_create_cart(user)
        cart_items = list(
            CartItem.objects.filter(cart=cart).select_related("product")
        )
        if not cart_items:
            raise ValidationError({"cart": "Your cart is empty."})

        # Lock products for update to prevent overselling
        product_ids = [item.product_id for item in cart_items]
        products_map = {
            p.id: p
            for p in Product.objects.select_for_update().filter(pk__in=product_ids)
        }

        # Validate stock
        for item in cart_items:
            product = products_map[item.product_id]
            if product.stock_quantity < item.quantity:
                raise ValidationError(
                    {
                        "cart": f"'{product.name}' only has {product.stock_quantity} in stock "
                        f"but your cart has {item.quantity}."
                    }
                )

        # Calculate total from snapshotted prices
        total = sum(
            products_map[item.product_id].price * item.quantity
            for item in cart_items
        )

        # Create Order
        order = Order.objects.create(
            user=user,
            status=Order.Status.PENDING,
            total_amount=total,
            shipping_address=shipping_address or {},
        )

        # Create OrderItems (price snapshot) + decrement stock
        for item in cart_items:
            product = products_map[item.product_id]
            OrderItem.objects.create(
                order=order,
                product=product,
                quantity=item.quantity,
                unit_price=product.price,  # snapshot
            )
            product.stock_quantity -= item.quantity
            product.save(update_fields=["stock_quantity"])

        # Clear cart after successful order
        CartItem.objects.filter(cart=cart).delete()

        logger.info("Order created: %s for %s — total %s", order.id, user.email, total)
        return order

    @staticmethod
    @transaction.atomic
    def create_guest_order(guest_email: str, guest_name: str, items_data: list, shipping_address: dict = None) -> Order:
        """
        Create an order for a guest (no user account required).
        items_data: list of {product_id, quantity}
        """
        if not items_data:
            raise ValidationError({"cart": "Your cart is empty."})

        product_ids = [item["product_id"] for item in items_data]
        products_map = {
            str(p.id): p
            for p in Product.objects.select_for_update().filter(
                pk__in=product_ids, status=Product.Status.PUBLISHED
            )
        }

        # Validate all products exist and have stock
        for item in items_data:
            product = products_map.get(str(item["product_id"]))
            if not product:
                raise ValidationError({"cart": f"Product not found or unavailable."})
            if product.stock_quantity < item["quantity"]:
                raise ValidationError(
                    {"cart": f"'{product.name}' only has {product.stock_quantity} in stock."}
                )

        total = sum(
            products_map[str(item["product_id"])].price * item["quantity"]
            for item in items_data
        )

        order = Order.objects.create(
            user=None,
            guest_email=guest_email,
            guest_name=guest_name,
            status=Order.Status.PENDING,
            total_amount=total,
            shipping_address=shipping_address or {},
        )

        for item in items_data:
            product = products_map[str(item["product_id"])]
            OrderItem.objects.create(
                order=order,
                product=product,
                quantity=item["quantity"],
                unit_price=product.price,
            )
            product.stock_quantity -= item["quantity"]
            product.save(update_fields=["stock_quantity"])

        logger.info("Guest order created: %s for %s — total %s", order.id, guest_email, total)
        return order

    @staticmethod
    def get_user_orders(user):
        return Order.objects.filter(user=user).prefetch_related(
            "items", "items__product"
        )

    @staticmethod
    def get_order_detail(user, order_id: str) -> Order:
        try:
            return Order.objects.prefetch_related(
                "items", "items__product", "items__product__images"
            ).get(pk=order_id, user=user)
        except Order.DoesNotExist:
            raise NotFound("Order not found.")

    @staticmethod
    @transaction.atomic
    def mark_order_paid(reference: str, transaction_id: str) -> Order:
        """
        Idempotent: if order is already PAID, return immediately without any write.

        Uses select_for_update() to prevent a race condition where two concurrent
        Celery workers (triggered by Paystack webhook retries) both see status=PENDING
        and both write PAID — without the lock both writes succeed causing duplicate
        processing.  With the lock, the second worker waits, then sees PAID and exits.
        """
        try:
            order = Order.objects.select_for_update().get(paystack_reference=reference)
        except Order.DoesNotExist:
            raise NotFound(f"Order with reference '{reference}' not found.")

        if order.status == Order.Status.PAID:
            # Idempotency guard — safe to call multiple times (Paystack retries webhooks)
            logger.info("Idempotency guard: order %s already PAID, skipping.", order.id)
            return order  # EARLY RETURN — no DB write

        order.status = Order.Status.PAID
        order.paystack_transaction_id = str(transaction_id)
        order.save(update_fields=["status", "paystack_transaction_id"])
        logger.info("Order %s marked PAID. Paystack transaction: %s", order.id, transaction_id)
        return order

    @staticmethod
    @transaction.atomic
    def cancel_order(user, order_id: str) -> Order:
        try:
            order = Order.objects.select_for_update().get(pk=order_id, user=user)
        except Order.DoesNotExist:
            raise NotFound("Order not found.")
        if order.status not in (Order.Status.PENDING, Order.Status.PAYMENT_PENDING):
            raise ValidationError(
                {"status": f"Cannot cancel an order in '{order.status}' status."}
            )
        # Restore stock
        for item in order.items.select_related("product").all():
            Product.objects.filter(pk=item.product_id).update(
                stock_quantity=F("stock_quantity") + item.quantity
            )
        order.status = Order.Status.CANCELLED
        order.save(update_fields=["status"])
        logger.info("Order cancelled: %s by %s", order.id, user.email)
        return order

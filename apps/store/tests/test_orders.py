"""Tests for order creation, price snapshot, stock decrement, and cancellation."""
import pytest
from rest_framework.test import APIClient

from apps.users.models import User
from apps.store.models import Category, Product


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def admin(db):
    return User.objects.create_user(
        email="admin@test.com", password="pass",
        first_name="Admin", last_name="Test",
        role="admin", is_email_verified=True,
        is_staff=True,
    )


@pytest.fixture
def user(db):
    return User.objects.create_user(
        email="buyer@test.com", password="pass123",
        first_name="Buyer", last_name="User",
        role="eaglet", is_email_verified=True,
    )


@pytest.fixture
def product(db, admin):
    cat = Category.objects.create(name="Merch", slug="merch")
    return Product.objects.create(
        name="Hoodie", slug="hoodie",
        category=cat, price="50.00",
        stock_quantity=10, status=Product.Status.PUBLISHED,
        created_by=admin,
    )


def add_to_cart(api, user, product, qty=1):
    api.force_authenticate(user=user)
    api.post("/api/v1/store/cart/items/", {
        "product_id": str(product.id), "quantity": qty
    }, format="json")


class TestCreateOrder:
    def test_create_order_from_cart_returns_201(self, api, user, product):
        add_to_cart(api, user, product, 2)
        r = api.post("/api/v1/store/orders/", {}, format="json")
        assert r.status_code == 201
        assert r.data["data"]["status"] == "pending"
        assert float(r.data["data"]["total_amount"]) == 100.0  # 2 x 50.00

    def test_order_items_snapshot_unit_price(self, api, user, product, admin):
        add_to_cart(api, user, product, 1)
        # Admin changes price AFTER item in cart but BEFORE checkout
        api.force_authenticate(user=admin)
        api.patch(f"/api/v1/store/products/{product.id}/", {"price": "999.00"}, format="json")
        api.force_authenticate(user=user)
        r = api.post("/api/v1/store/orders/", {}, format="json")
        # Order should snapshot the price at checkout time (999.00, not 50.00)
        assert float(r.data["data"]["items"][0]["unit_price"]) == 999.0

    def test_stock_decremented_after_order(self, api, user, product, db):
        add_to_cart(api, user, product, 3)
        api.post("/api/v1/store/orders/", {}, format="json")
        product.refresh_from_db()
        assert product.stock_quantity == 7  # 10 - 3

    def test_cart_cleared_after_order(self, api, user, product):
        add_to_cart(api, user, product, 1)
        api.post("/api/v1/store/orders/", {}, format="json")
        r = api.get("/api/v1/store/cart/")
        assert r.data["data"]["items"] == []

    def test_empty_cart_returns_400(self, api, user):
        api.force_authenticate(user=user)
        r = api.post("/api/v1/store/orders/", {}, format="json")
        assert r.status_code == 400

    def test_unauthenticated_cannot_create_order(self, api, product):
        r = api.post("/api/v1/store/orders/", {}, format="json")
        assert r.status_code == 401


class TestCancelOrder:
    def test_pending_order_can_be_cancelled(self, api, user, product):
        add_to_cart(api, user, product, 2)
        r = api.post("/api/v1/store/orders/", {}, format="json")
        order_id = r.data["data"]["id"]
        r2 = api.post(f"/api/v1/store/orders/{order_id}/cancel/", {}, format="json")
        assert r2.status_code == 200
        assert r2.data["data"]["status"] == "cancelled"

    def test_stock_restored_on_cancel(self, api, user, product, db):
        add_to_cart(api, user, product, 3)
        r = api.post("/api/v1/store/orders/", {}, format="json")
        order_id = r.data["data"]["id"]
        api.post(f"/api/v1/store/orders/{order_id}/cancel/", {}, format="json")
        product.refresh_from_db()
        assert product.stock_quantity == 10  # fully restored

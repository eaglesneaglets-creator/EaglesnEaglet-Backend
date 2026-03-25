"""Tests for cart endpoints."""
import pytest
from rest_framework.test import APIClient

from apps.users.models import User
from apps.store.models import Category, Product


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def user(db):
    return User.objects.create_user(
        email="buyer@test.com", password="pass123",
        first_name="Buyer", last_name="User",
        role="eaglet", is_email_verified=True,
    )


@pytest.fixture
def admin(db):
    return User.objects.create_user(
        email="admin@test.com", password="pass123",
        first_name="Admin", last_name="Test",
        role="admin", is_email_verified=True,
        is_staff=True,
    )


@pytest.fixture
def product(db, admin):
    cat = Category.objects.create(name="Merch", slug="merch")
    return Product.objects.create(
        name="T-Shirt", slug="t-shirt",
        category=cat, price="20.00",
        stock_quantity=5, status=Product.Status.PUBLISHED,
        created_by=admin,
    )


class TestAddToCart:
    def test_add_product_to_cart(self, api, user, product):
        api.force_authenticate(user=user)
        r = api.post("/api/v1/store/cart/items/", {
            "product_id": str(product.id), "quantity": 2
        }, format="json")
        assert r.status_code == 201
        assert r.data["data"]["quantity"] == 2

    def test_adding_same_product_increments_quantity(self, api, user, product):
        api.force_authenticate(user=user)
        api.post("/api/v1/store/cart/items/", {"product_id": str(product.id), "quantity": 1}, format="json")
        api.post("/api/v1/store/cart/items/", {"product_id": str(product.id), "quantity": 2}, format="json")
        r = api.get("/api/v1/store/cart/")
        items = r.data["data"]["items"]
        assert items[0]["quantity"] == 3

    def test_cannot_add_more_than_stock(self, api, user, product):
        api.force_authenticate(user=user)
        r = api.post("/api/v1/store/cart/items/", {
            "product_id": str(product.id), "quantity": 99
        }, format="json")
        assert r.status_code == 400

    def test_unauthenticated_cannot_add_to_cart(self, api, product):
        r = api.post("/api/v1/store/cart/items/", {
            "product_id": str(product.id), "quantity": 1
        }, format="json")
        assert r.status_code == 401


class TestGetCart:
    def test_empty_cart_returns_zero_total(self, api, user):
        api.force_authenticate(user=user)
        r = api.get("/api/v1/store/cart/")
        assert r.status_code == 200
        assert r.data["data"]["total"] == 0
        assert r.data["data"]["items"] == []

    def test_cart_total_is_correct(self, api, user, product):
        api.force_authenticate(user=user)
        api.post("/api/v1/store/cart/items/", {"product_id": str(product.id), "quantity": 3}, format="json")
        r = api.get("/api/v1/store/cart/")
        assert float(r.data["data"]["total"]) == 60.0  # 3 x 20.00

"""Tests for product endpoints — public read, admin-only write."""
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
        email="admin@test.com", password="pass123",
        first_name="Admin", last_name="User",
        role="admin", is_email_verified=True,
        is_staff=True,
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com", password="pass123",
        first_name="Test", last_name="Eaglet",
        role="eaglet", is_email_verified=True,
    )


@pytest.fixture
def category(db):
    return Category.objects.create(name="Merchandise", slug="merchandise")


@pytest.fixture
def product(db, category, admin):
    return Product.objects.create(
        name="Eagles Cap", slug="eagles-cap",
        category=category, price="25.00",
        stock_quantity=10, status=Product.Status.PUBLISHED,
        created_by=admin,
    )


class TestProductList:
    def test_public_can_list_published_products(self, api, product):
        r = api.get("/api/v1/store/products/")
        assert r.status_code == 200
        assert r.data["success"] is True
        names = [p["name"] for p in r.data["data"]]
        assert "Eagles Cap" in names

    def test_draft_product_not_visible_to_public(self, api, db, admin, category):
        Product.objects.create(
            name="Draft Item", slug="draft-item",
            category=category, price="10.00",
            stock_quantity=5, status=Product.Status.DRAFT,
            created_by=admin,
        )
        r = api.get("/api/v1/store/products/")
        names = [p["name"] for p in r.data["data"]]
        assert "Draft Item" not in names


class TestProductCreate:
    def test_admin_can_create_product(self, api, admin, category):
        api.force_authenticate(user=admin)
        r = api.post("/api/v1/store/products/", {
            "name": "New Cap",
            "price": "30.00",
            "stock_quantity": 5,
            "category_id": str(category.id),
            "status": "published",
        }, format="json")
        assert r.status_code == 201
        assert r.data["data"]["name"] == "New Cap"

    def test_eaglet_cannot_create_product(self, api, eaglet, category):
        api.force_authenticate(user=eaglet)
        r = api.post("/api/v1/store/products/", {
            "name": "Hack", "price": "1.00", "stock_quantity": 1,
        }, format="json")
        assert r.status_code == 403

    def test_unauthenticated_cannot_create_product(self, api, category):
        r = api.post("/api/v1/store/products/", {
            "name": "Hack", "price": "1.00", "stock_quantity": 1,
        }, format="json")
        assert r.status_code == 401


class TestProductUpdate:
    def test_admin_can_update_product(self, api, admin, product):
        api.force_authenticate(user=admin)
        r = api.patch(f"/api/v1/store/products/{product.id}/", {
            "price": "35.00"
        }, format="json")
        assert r.status_code == 200
        assert r.data["data"]["price"] == "35.00"

    def test_eaglet_cannot_update_product(self, api, eaglet, product):
        api.force_authenticate(user=eaglet)
        r = api.patch(f"/api/v1/store/products/{product.id}/", {"price": "1.00"}, format="json")
        assert r.status_code == 403

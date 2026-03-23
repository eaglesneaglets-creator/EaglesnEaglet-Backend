"""
Tests for manual point award endpoint (MM-16).
"""
import pytest
from rest_framework.test import APIClient

from apps.users.models import User
from apps.nests.models import Nest, NestMembership
from apps.points.models import PointTransaction
from apps.notifications.models import Notification


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@test.com",
        password="testpass123",
        first_name="Test",
        last_name="Eagle",
        role="eagle",
        is_email_verified=True,
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com",
        password="testpass123",
        first_name="Test",
        last_name="Eaglet",
        role="eaglet",
        is_email_verified=True,
    )


@pytest.fixture
def other_eaglet(db):
    return User.objects.create_user(
        email="other@test.com",
        password="testpass123",
        first_name="Other",
        last_name="Eaglet",
        role="eaglet",
        is_email_verified=True,
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(
        name="Test Nest",
        description="A test nest",
        eagle=eagle,
    )


@pytest.fixture
def membership(db, nest, eaglet):
    return NestMembership.objects.create(
        nest=nest,
        user=eaglet,
        status="active",
    )


@pytest.fixture
def admin_user(db):
    return User.objects.create_user(
        email="admin@test.com",
        password="testpass123",
        first_name="Admin",
        last_name="User",
        role="admin",
        is_email_verified=True,
        is_staff=True,
    )


AWARD_URL = "/api/v1/points/award/"


class TestAwardEndpoint:

    def test_eagle_can_award_to_own_eaglet(self, api_client, eagle, eaglet, nest, membership):
        """Eagle can award points to an eaglet in their nest."""
        api_client.force_authenticate(user=eagle)
        resp = api_client.post(AWARD_URL, {
            "eaglet_id": str(eaglet.id),
            "points": 50,
            "description": "Great performance this week",
            "nest_id": str(nest.id),
        })
        assert resp.status_code == 201
        assert resp.data["success"] is True
        assert PointTransaction.objects.filter(user=eaglet, source="manual").count() == 1

    def test_eagle_cannot_award_to_eaglet_in_another_nest(
        self, api_client, eagle, other_eaglet, nest
    ):
        """Eagle cannot award to an eaglet not in their nest.
        When a nest_id is provided and the eaglet isn't a member,
        the service raises ValidationError (400) — a data validation error,
        not a permissions error. When no nest_id is given, it raises
        PermissionDenied (403). Both correctly block the award.
        """
        api_client.force_authenticate(user=eagle)
        resp = api_client.post(AWARD_URL, {
            "eaglet_id": str(other_eaglet.id),
            "points": 50,
            "description": "Trying to award outside nest",
            "nest_id": str(nest.id),
        })
        # 400: eaglet not in the specified nest (ValidationError from service)
        assert resp.status_code == 400

    def test_eaglet_cannot_call_award_endpoint(self, api_client, eaglet, eagle, nest, membership):
        """Eaglets cannot award points — 403."""
        api_client.force_authenticate(user=eaglet)
        resp = api_client.post(AWARD_URL, {
            "eaglet_id": str(eagle.id),
            "points": 10,
            "description": "Trying to award as eaglet",
        })
        assert resp.status_code == 403

    def test_award_rejects_zero_points(self, api_client, eagle, eaglet, nest, membership):
        """Points must be at least 1."""
        api_client.force_authenticate(user=eagle)
        resp = api_client.post(AWARD_URL, {
            "eaglet_id": str(eaglet.id),
            "points": 0,
            "description": "Testing zero points",
        })
        assert resp.status_code == 400

    def test_award_rejects_short_description(self, api_client, eagle, eaglet, nest, membership):
        """Description must be at least 5 characters."""
        api_client.force_authenticate(user=eagle)
        resp = api_client.post(AWARD_URL, {
            "eaglet_id": str(eaglet.id),
            "points": 10,
            "description": "Hi",
        })
        assert resp.status_code == 400

    def test_award_creates_notification(self, api_client, eagle, eaglet, nest, membership):
        """A notification is created for the eaglet when points are awarded."""
        api_client.force_authenticate(user=eagle)
        api_client.post(AWARD_URL, {
            "eaglet_id": str(eaglet.id),
            "points": 25,
            "description": "Well done on the assignment",
            "nest_id": str(nest.id),
        })
        assert Notification.objects.filter(
            recipient=eaglet, notification_type="points_awarded"
        ).count() == 1

    def test_admin_can_award_to_any_eaglet(self, api_client, admin_user, other_eaglet):
        """Admins bypass the nest ownership check.
        Note: nest_id is optional in ManualPointAwardSerializer (required=False),
        so omitting it is valid and will not cause a 400.
        """
        api_client.force_authenticate(user=admin_user)
        resp = api_client.post(AWARD_URL, {
            "eaglet_id": str(other_eaglet.id),
            "points": 100,
            "description": "Admin override award for test",
        })
        assert resp.status_code == 201

"""
Points URL Configuration

Routes for points dashboard, transactions, leaderboard, badges,
and admin configuration.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    PointsViewSet,
    LeaderboardViewSet,
    BadgeViewSet,
    PointConfigViewSet,
)

router = DefaultRouter()
router.register(r"leaderboard", LeaderboardViewSet, basename="leaderboard")
router.register(r"badges", BadgeViewSet, basename="badge")
router.register(r"config", PointConfigViewSet, basename="point-config")

urlpatterns = [
    path("", include(router.urls)),
    path(
        "my/",
        PointsViewSet.as_view({"get": "my_points"}),
        name="my-points",
    ),
    path(
        "transactions/",
        PointsViewSet.as_view({"get": "transactions"}),
        name="point-transactions",
    ),
    path(
        "award/",
        PointsViewSet.as_view({"post": "award"}),
        name="award-points",
    ),
    path(
        "my-badges/",
        BadgeViewSet.as_view({"get": "my_badges"}),
        name="my-badges",
    ),
]

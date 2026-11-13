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
    PointsPolicyViewSet,
)

router = DefaultRouter()
router.register(r"leaderboard", LeaderboardViewSet, basename="leaderboard")
router.register(r"badges", BadgeViewSet, basename="badge")
router.register(r"config", PointConfigViewSet, basename="point-config")

# NOTE: a manual ``ViewSet.as_view({...})`` does NOT apply the per-action
# ``@action(permission_classes=...)`` kwargs (only routers do). Pass them
# explicitly via ``**ViewSet.<action>.kwargs`` — core/tests/test_route_permissions.py
# fails the build if a route drops them.
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
        PointsViewSet.as_view({"post": "award"}, **PointsViewSet.award.kwargs),
        name="award-points",
    ),
    path(
        "award-budget/",
        PointsViewSet.as_view({"get": "award_budget"}, **PointsViewSet.award_budget.kwargs),
        name="award-budget",
    ),
    path(
        "policy/",
        PointsPolicyViewSet.as_view({"get": "list", "patch": "partial_update"}),
        name="points-policy",
    ),
    path(
        "my-badges/",
        BadgeViewSet.as_view({"get": "my_badges"}),
        name="my-badges",
    ),
]

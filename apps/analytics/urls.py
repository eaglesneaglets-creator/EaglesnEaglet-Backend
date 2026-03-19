"""
Analytics URL Configuration

Routes for dashboard analytics endpoints.
"""

from django.urls import path

from .views import AnalyticsViewSet

urlpatterns = [
    path(
        "eagle-dashboard/",
        AnalyticsViewSet.as_view({"get": "eagle_dashboard"}),
        name="eagle-dashboard",
    ),
    path(
        "eaglet-dashboard/",
        AnalyticsViewSet.as_view({"get": "eaglet_dashboard"}),
        name="eaglet-dashboard",
    ),
    path(
        "admin-dashboard/",
        AnalyticsViewSet.as_view({"get": "admin_dashboard"}),
        name="admin-dashboard",
    ),
    path(
        "nest/<uuid:pk>/",
        AnalyticsViewSet.as_view({"get": "nest_analytics"}),
        name="nest-analytics",
    ),
    path(
        "check-in/",
        AnalyticsViewSet.as_view({"post": "check_in"}),
        name="check-in",
    ),
]

"""
Admin-only routes for nests app (plan 14-04).

Mounted at /api/v1/admin/ from project urls. Currently exposes mentee-level
config CRUD; expand here if the admin surface grows.
"""

from django.urls import path

from .views import MenteeLevelConfigViewSet


urlpatterns = [
    path(
        "mentee-levels/",
        MenteeLevelConfigViewSet.as_view({"get": "list", "patch": "bulk_update"}),
        name="admin-mentee-levels",
    ),
]

"""
Admin-only routes for nests app (plan 14-04).

Mounted at /api/v1/admin/ from project urls. Currently exposes mentee-level
config CRUD; expand here if the admin surface grows.
"""

from django.urls import path

from .views import MenteeLevelConfigViewSet
from .views_admin_nests import AdminNestViewSet


urlpatterns = [
    path(
        "mentee-levels/",
        MenteeLevelConfigViewSet.as_view({"get": "list", "patch": "bulk_update"}),
        name="admin-mentee-levels",
    ),
    # Phase 27-01: admin nest oversight (superadmin only).
    path(
        "nests/",
        AdminNestViewSet.as_view({"get": "list", "post": "create"}),
        name="admin-nests",
    ),
    path(
        "nests/<uuid:pk>/",
        AdminNestViewSet.as_view({"get": "retrieve"}),
        name="admin-nest-detail",
    ),
    path(
        "nests/<uuid:pk>/activity/",
        AdminNestViewSet.as_view({"get": "activity"}),
        name="admin-nest-activity",
    ),
    path(
        "nests/<uuid:pk>/archive/",
        AdminNestViewSet.as_view({"patch": "archive"}),
        name="admin-nest-archive",
    ),
    path(
        "nests/<uuid:pk>/members/<uuid:membership_id>/",
        AdminNestViewSet.as_view({"delete": "remove_member"}),
        name="admin-nest-remove-member",
    ),
]

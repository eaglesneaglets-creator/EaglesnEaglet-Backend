"""
Admin nest oversight views (Phase 27-01).

Superadmin-only platform-wide nest management. Kept separate from views.py
(mentor/eaglet surface). Mounted under /api/v1/admin/nests/.
"""

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from core.pagination import StandardResultsSetPagination
from core.permissions import IsSuperAdmin

from .serializers_admin import (
    AdminNestListSerializer,
    AdminNestDetailSerializer,
    AdminNestCreateSerializer,
    NestActivitySerializer,
)
from .services_activity import NestAdminService
from .models import Nest


class AdminNestViewSet(ViewSet):
    """
    Platform-wide nest oversight (superadmin only).

    GET    /admin/nests/                          → list all nests (filters + pagination)
    POST   /admin/nests/                          → create nest on behalf of a mentor
    GET    /admin/nests/{id}/                      → nest detail (members + content + activity)
    GET    /admin/nests/{id}/activity/            → paginated activity log
    PATCH  /admin/nests/{id}/archive/             → archive (soft-delete + deactivate)
    DELETE /admin/nests/{id}/members/{mid}/       → remove a member
    """

    permission_classes = [IsAuthenticated, IsSuperAdmin]

    def list(self, request):
        params = request.query_params
        # Normalise "all" / empty → None so the service skips the filter.
        raw_status = params.get("status")
        raw_category = params.get("category")
        qs = NestAdminService.list_all_nests(
            status=None if raw_status in (None, "", "all") else raw_status,
            category=None if raw_category in (None, "", "all") else raw_category,
            search=params.get("search") or None,
            include_archived=params.get("include_archived") == "true",
        )
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = AdminNestListSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def retrieve(self, request, pk=None):
        try:
            nest = (
                Nest.all_objects.select_related("eagle")
                .prefetch_related("memberships__user", "resources__uploaded_by", "activities__actor")
                .get(pk=pk)
            )
        except Nest.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Nest not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Attach the annotated count the serializer's _derive_status expects.
        nest.annotated_member_count = nest.member_count
        return Response({"success": True, "data": AdminNestDetailSerializer(nest).data})

    def create(self, request):
        serializer = AdminNestCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        nest = NestAdminService.create_on_behalf(request.user, dict(serializer.validated_data))
        nest.annotated_member_count = nest.member_count
        return Response(
            {"success": True, "data": AdminNestDetailSerializer(nest).data},
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"], url_path="activity")
    def activity(self, request, pk=None):
        qs = NestAdminService.get_nest_activity(pk)
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = NestActivitySerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(detail=True, methods=["patch"], url_path="archive")
    def archive(self, request, pk=None):
        nest = NestAdminService.archive_nest(request.user, pk)
        nest.annotated_member_count = nest.member_count
        return Response({"success": True, "data": AdminNestListSerializer(nest).data})

    @action(
        detail=True,
        methods=["delete"],
        url_path=r"members/(?P<membership_id>[^/.]+)",
    )
    def remove_member(self, request, pk=None, membership_id=None):
        NestAdminService.remove_member(request.user, pk, membership_id)
        return Response(
            {"success": True, "data": {"message": "Member removed."}},
            status=status.HTTP_200_OK,
        )

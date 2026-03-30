"""
Points Views

API endpoints for points dashboard, transactions, leaderboard,
badges, and admin configuration.
"""

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from core.permissions import IsEagleOrAdmin, IsAdmin

from .serializers import (
    PointConfigurationSerializer,
    PointTransactionSerializer,
    ManualPointAwardSerializer,
    UserPointsSummarySerializer,
    LeaderboardEntrySerializer,
    BadgeSerializer,
    UserBadgeSerializer,
)
from .services import PointService
from .models import PointConfiguration, Badge


class PointsViewSet(ViewSet):
    """
    Points endpoints for users.

    GET  /points/my/              → user's points summary
    GET  /points/transactions/    → user's transaction history
    POST /points/award/           → manual award (Eagle only)
    """

    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["get"], url_path="my")
    def my_points(self, request):
        """Get current user's points summary."""
        user = request.user
        data = PointService.get_user_points_summary(user)
        return Response({"success": True, "data": data})

    @action(detail=False, methods=["get"], url_path="transactions")
    def transactions(self, request):
        """List user's point transactions."""
        txns = PointService.get_user_transactions(request.user)
        serializer = PointTransactionSerializer(txns, many=True)
        return Response({"success": True, "data": serializer.data})

    @action(
        detail=False,
        methods=["post"],
        url_path="award",
        permission_classes=[IsAuthenticated, IsEagleOrAdmin],
    )
    def award(self, request):
        """Eagle manually awards points to an Eaglet."""
        serializer = ManualPointAwardSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from django.contrib.auth import get_user_model
        User = get_user_model()

        try:
            eaglet = User.objects.get(pk=serializer.validated_data["eaglet_id"])
        except User.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Eaglet not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        nest = None
        nest_id = serializer.validated_data.get("nest_id")
        if nest_id:
            from apps.nests.models import Nest
            try:
                nest = Nest.objects.get(pk=nest_id)
            except Nest.DoesNotExist:
                return Response(
                    {"success": False, "error": {"message": "Nest not found."}},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # SECURITY: Eagles can only award points within their own nest.
            # Admins may award across any nest.
            if request.user.role != 'admin' and nest.eagle_id != request.user.id:
                return Response(
                    {"success": False, "error": {"message": "You can only award points in your own Nest."}},
                    status=status.HTTP_403_FORBIDDEN,
                )

        txn = PointService.award_manual_points(
            eagle=request.user,
            eaglet=eaglet,
            points=serializer.validated_data["points"],
            description=serializer.validated_data["description"],
            nest=nest,
        )
        return Response(
            {"success": True, "data": PointTransactionSerializer(txn).data},
            status=status.HTTP_201_CREATED,
        )


class LeaderboardViewSet(ViewSet):
    """
    Leaderboard endpoint.

    GET /points/leaderboard/?scope=global&period=all
    """

    permission_classes = [IsAuthenticated]

    def list(self, request):
        """Get leaderboard rankings."""
        scope = request.query_params.get("scope", "global")
        period = request.query_params.get("period", "all")
        nest_id = request.query_params.get("nest")

        entries = PointService.get_leaderboard(scope, nest_id, period)

        # Add rank numbers
        ranked = []
        for idx, entry in enumerate(entries, 1):
            entry["rank"] = idx
            ranked.append(entry)

        serializer = LeaderboardEntrySerializer(ranked, many=True)
        return Response({"success": True, "data": serializer.data})


class BadgeViewSet(ViewSet):
    """Badge endpoints."""

    permission_classes = [IsAuthenticated]

    def list(self, request):
        """List all badges with per-user earned status and progress."""
        badges = Badge.objects.all().order_by("criteria_type", "criteria_value")
        serializer = BadgeSerializer(badges, many=True, context={"request": request})
        return Response({"success": True, "data": serializer.data})

    def retrieve(self, request, pk=None):
        """Get a single badge by id."""
        try:
            badge = Badge.objects.get(pk=pk)
        except Badge.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Badge not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = BadgeSerializer(badge, context={"request": request})
        return Response({"success": True, "data": serializer.data})

    @action(detail=False, methods=["get"], url_path="my")
    def my_badges(self, request):
        """List only earned badges for current user."""
        user_badges = PointService.get_user_badges(request.user)
        serializer = UserBadgeSerializer(user_badges, many=True)
        return Response({"success": True, "data": serializer.data})


class PointConfigViewSet(ViewSet):
    """Admin-only point configuration management."""

    permission_classes = [IsAuthenticated, IsAdmin]

    def list(self, request):
        """List all point configurations."""
        configs = PointConfiguration.objects.all()
        serializer = PointConfigurationSerializer(configs, many=True)
        return Response({"success": True, "data": serializer.data})

    def partial_update(self, request, pk=None):
        """Update a point configuration."""
        try:
            config = PointConfiguration.objects.get(pk=pk)
        except PointConfiguration.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Configuration not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = PointConfigurationSerializer(
            config, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"success": True, "data": serializer.data})

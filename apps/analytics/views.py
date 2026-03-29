"""
Analytics Views

Dashboard API endpoints for Eagle, Eaglet, and Admin views.
"""

from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from core.permissions import IsAdmin, IsNestMember

from .services import AnalyticsService


class AnalyticsViewSet(ViewSet):
    """
    Dashboard analytics endpoints.

    GET /analytics/eagle-dashboard/   → Eagle stats
    GET /analytics/eaglet-dashboard/  → Eaglet stats
    GET /analytics/admin-dashboard/   → Admin stats (admin only)
    GET /analytics/nest/{id}/         → Nest analytics
    """

    permission_classes = [IsAuthenticated]

    def eagle_dashboard(self, request):
        """Eagle dashboard stats (cached for 5 min)."""
        from django.core.cache import cache
        cache_key = f"eagle_stats_{request.user.id}"
        data = cache.get(cache_key)
        
        if not data:
            data = AnalyticsService.get_eagle_dashboard_stats(request.user)
            cache.set(cache_key, data, 300)
            
        return Response({"success": True, "data": data})

    def eaglet_dashboard(self, request):
        """Eaglet dashboard stats (cached for 5 min)."""
        from django.core.cache import cache
        cache_key = f"eaglet_stats_{request.user.id}"
        data = cache.get(cache_key)
        
        if not data:
            data = AnalyticsService.get_eaglet_dashboard_stats(request.user)
            cache.set(cache_key, data, 300)
            
        return Response({"success": True, "data": data})

    def admin_dashboard(self, request):
        """Admin dashboard stats (admin only, cached for 10 min)."""
        if not (request.user.is_staff or request.user.is_superuser):
            return Response(
                {"success": False, "error": {"message": "Admin access required."}},
                status=403,
            )
            
        from django.core.cache import cache
        cache_key = "admin_stats_global"
        data = cache.get(cache_key)
        
        if not data:
            data = AnalyticsService.get_admin_dashboard_stats()
            cache.set(cache_key, data, 600)
            
        return Response({"success": True, "data": data})

    def nest_analytics(self, request, pk=None):
        """Analytics for a specific Nest (owner or member only, cached for 5 min)."""
        from apps.nests.models import Nest, NestMembership
        from django.core.cache import cache

        if not (request.user.is_staff or request.user.is_superuser):
            is_owner = Nest.objects.filter(pk=pk, eagle=request.user).exists()
            is_member = NestMembership.objects.filter(
                nest_id=pk, user=request.user, status="active"
            ).exists()
            if not is_owner and not is_member:
                return Response(
                    {"success": False, "error": {"message": "You must be a member or owner of this Nest."}},
                    status=403,
                )

        cache_key = f"nest_stats_{pk}"
        data = cache.get(cache_key)
        
        if not data:
            data = AnalyticsService.get_nest_analytics(pk)
            cache.set(cache_key, data, 300)
            
        return Response({"success": True, "data": data})

    def check_in(self, request):
        """Record a daily check-in and award points."""
        from django.db import transaction
        from django.contrib.auth import get_user_model
        from apps.points.services import PointService
        from apps.points.models import PointTransaction

        today = timezone.now().date()
        User = get_user_model()

        with transaction.atomic():
            # Lock the user row to serialize concurrent check-in requests.
            # Any parallel request for the same user will block here until
            # this transaction commits, preventing the duplicate-award race.
            User.objects.select_for_update().get(id=request.user.id)

            # Check if already checked in today (now safe under the lock)
            already_checked_in = PointTransaction.objects.filter(
                user=request.user,
                activity_type="check_in",
                created_at__date=today,
            ).exists()

            if already_checked_in:
                return Response({
                    "success": False,
                    "error": {"message": "You have already checked in today."}
                }, status=400)

            # Award points (also runs inside this atomic block)
            txn = PointService.award_points(request.user, "check_in")

        if not txn:
            return Response({
                "success": False,
                "error": {"message": "Check-in point configuration not found or disabled."}
            }, status=500)

        # Clear cached stats so dashboard reflects new points immediately
        AnalyticsService.clear_dashboard_cache(request.user.id, request.user.role)

        return Response({
            "success": True,
            "data": {
                "points_earned": txn.points,
                "total_points": PointService.get_user_total_points(request.user),
                "streak": PointService.get_user_streak(request.user)
            }
        })

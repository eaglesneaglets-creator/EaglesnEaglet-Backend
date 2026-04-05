"""
Analytics Services

Aggregation queries for Eagle, Eaglet, and Admin dashboards.
Each method returns a dictionary ready for serialization.
"""

import logging
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Count, Sum, Q
from django.utils import timezone

from apps.nests.models import Nest, NestMembership, MentorshipRequest
from apps.content.models import ContentModule, ContentProgress, AssignmentSubmission
from apps.points.models import PointTransaction
from apps.points.services import PointService

logger = logging.getLogger(__name__)
User = get_user_model()


class AnalyticsService:
    """Business logic for dashboard statistics aggregation."""

    @staticmethod
    def clear_dashboard_cache(user_id: str, role: str) -> None:
        """Clear cached dashboard stats for a user."""
        if role == "eaglet":
            cache.delete(f"eaglet_stats_{user_id}")
        elif role == "eagle":
            cache.delete(f"eagle_stats_{user_id}")
        elif role == "admin":
            cache.delete("admin_stats_global")
        logger.info("Cleared dashboard cache for user %s (%s)", user_id, role)

    @staticmethod
    def get_eagle_dashboard_stats(eagle) -> dict:
        """Stats for the Eagle (mentor) dashboard."""
        cache_key = f"eagle_stats_{eagle.id}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        owned_nests = Nest.objects.filter(eagle=eagle).annotate(
            _member_count=Count(
                'memberships',
                filter=Q(memberships__status='active') & ~Q(memberships__user=eagle)
            )
        )
        nest_ids = list(owned_nests.values_list("id", flat=True))

        total_eaglets = NestMembership.objects.filter(
            nest_id__in=nest_ids, status="active"
        ).exclude(user=eagle).values("user").distinct().count()

        pending_requests = MentorshipRequest.objects.filter(
            nest_id__in=nest_ids, status="pending"
        ).count()

        total_modules = ContentModule.objects.filter(
            nest_id__in=nest_ids
        ).count()

        points_awarded = PointTransaction.objects.filter(
            nest_id__in=nest_ids, source="manual"
        ).aggregate(total=Sum("points"))["total"] or 0

        nest_summaries = []
        for nest in owned_nests[:5]:
            nest_summaries.append({
                "id": str(nest.id),
                "name": nest.name,
                "member_count": nest._member_count,                   # from annotation, no extra SQL
                "is_full": nest._member_count >= nest.max_members,    # pure Python
            })

        # Performance list for Eagle dashboard
        eaglets_qs = NestMembership.objects.filter(
            nest_id__in=nest_ids, status="active"
        ).exclude(user=eagle).select_related("user", "nest").order_by("-progress_percentage")[:5]

        eaglets_performance = []
        for membership in eaglets_qs:
            eaglets_performance.append({
                "id": str(membership.user.id),
                "name": membership.user.full_name,
                "nest_id": str(membership.nest.id),
                "nest_name": membership.nest.name,
                "progress": membership.progress_percentage,
                "status": membership.user.status,
                "avatar": membership.user.avatar.url if membership.user.avatar else membership.user.profile_picture_url,
            })

        # Upcoming sessions
        from apps.nests.models import NestEvent
        upcoming_sessions_qs = NestEvent.objects.filter(
            nest_id__in=nest_ids,
            event_date__gte=timezone.now()
        ).select_related("nest").order_by("event_date")[:5]

        upcoming_sessions = []
        for event in upcoming_sessions_qs:
            upcoming_sessions.append({
                "id": str(event.id),
                "title": event.title,
                "date": event.event_date.isoformat(),
                "nest_name": event.nest.name,
                "link": event.meeting_link,
            })

        result = {
            "total_eaglets": total_eaglets,
            "pending_requests": pending_requests,
            "total_modules": total_modules,
            "points_awarded": points_awarded,
            "nests": nest_summaries,
            "active_nests": sum(1 for n in owned_nests if n.is_active),  # queryset already evaluated
            "eaglets": eaglets_performance,
            "upcoming_sessions": upcoming_sessions,
        }
        cache.set(cache_key, result, timeout=300)  # 5-minute cache
        return result

    @staticmethod
    def get_eaglet_dashboard_stats(eaglet) -> dict:
        """Stats for the Eaglet (mentee) dashboard."""
        cache_key = f"eaglet_stats_{eaglet.id}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        total_points = PointService.get_user_total_points(eaglet)
        streak = PointService.get_user_streak(eaglet)

        progress_qs = ContentProgress.objects.filter(user=eaglet)
        completed_items = progress_qs.filter(status="completed").count()
        in_progress_items = progress_qs.filter(status="in_progress").count()

        modules_completed = (
            progress_qs.filter(status="completed")
            .values("content_item__module")
            .distinct()
            .count()
        )

        memberships = NestMembership.objects.filter(
            user=eaglet, status="active"
        ).select_related("nest__eagle")

        nest_info = []
        nest_ids = []
        for m in memberships:
            nest_ids.append(m.nest.id)
            if len(nest_info) < 3:
                nest_info.append({
                    "id": str(m.nest.id),
                    "name": m.nest.name,
                    "eagle_name": m.nest.eagle.full_name,
                    "progress": m.progress_percentage,
                })

        pending_requests = MentorshipRequest.objects.filter(
            eaglet=eaglet, status="pending"
        ).count()

        # Recent Content Items from modules in the eaglet's joined nests
        from apps.content.models import ContentItem
        recent_items_qs = ContentItem.objects.filter(
            module__nest_id__in=nest_ids,
            module__is_published=True,
        ).select_related("module__nest").order_by("-created_at")[:5]

        recent_content = []
        for item in recent_items_qs:
            recent_content.append({
                "id": str(item.id),
                "title": item.title,
                "type": item.content_type,
                "nestName": item.module.nest.name,
                "date": item.created_at.isoformat(),
            })

        # Leaderboard Preview
        leaderboard_data = PointService.get_leaderboard(scope="global", period="month")[:5]
        leaderboard_preview = []
        for entry in leaderboard_data:
            leaderboard_preview.append({
                "id": str(entry["user__id"]),
                "name": f"{entry['user__first_name']} {entry['user__last_name']}".strip(),
                "points": entry["total_points"],
            })

        # Weekly Check-ins (last 7 days)
        today = timezone.now().date()
        checkin_dates = set(
            PointTransaction.objects.filter(
                user=eaglet,
                activity_type="check_in",
                created_at__date__gte=today - timedelta(days=6)
            ).values_list("created_at__date", flat=True)
        )
        
        # [Sunday, ..., Saturday] for the current week
        # weekday(): 0=Mon, ..., 6=Sun. Sunday should be 0 for our loop.
        days_since_sunday = (today.weekday() + 1) % 7
        start_of_week = today - timedelta(days=days_since_sunday)
        
        weekly_checkins = []
        for i in range(7):
            date = start_of_week + timedelta(days=i)
            # Only show as checked if the date is today or in the past
            if date <= today:
                weekly_checkins.append(date in checkin_dates)
            else:
                weekly_checkins.append(False)

        result = {
            "points": total_points,  # Aliased for frontend
            "total_points": total_points,
            "streak": streak,        # Aliased for frontend
            "streak_days": streak,
            "completed_items": completed_items,
            "in_progress_items": in_progress_items,
            "modules_completed": modules_completed,
            "nests": nest_info,
            "pending_requests": pending_requests,
            "recent_content": recent_content,
            "leaderboard_preview": leaderboard_preview,
            "weekly_checkins": weekly_checkins,
            "has_checked_in_today": today in checkin_dates,
        }
        cache.set(cache_key, result, timeout=300)  # 5-minute cache
        return result

    @staticmethod
    def get_admin_dashboard_stats() -> dict:
        """Stats for the Admin dashboard."""
        cache_key = "admin_stats_global"
        cached = cache.get(cache_key)
        if cached:
            return cached

        # Single aggregation for user stats (total + new this month in one query)
        month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        user_stats = User.objects.aggregate(
            total=Count('id'),
            new_this_month=Count('id', filter=Q(date_joined__gte=month_start)),
        )

        # Role breakdown — one query
        role_counts = dict(
            User.objects.values_list("role").annotate(count=Count("id")).order_by()
        )

        active_nests = Nest.objects.filter(is_active=True).count()

        # Pending KYC — two separate COUNT queries (each is a single fast query)
        from apps.users.models import MentorKYC, MenteeKYC
        pending_mentor_kyc = MentorKYC.objects.filter(status="submitted").count()
        pending_mentee_kyc = MenteeKYC.objects.filter(status="submitted").count()

        result = {
            "total_users": user_stats['total'],
            "active_nests": active_nests,
            "role_counts": role_counts,
            "new_users_this_month": user_stats['new_this_month'],
            "pending_kyc": pending_mentor_kyc + pending_mentee_kyc,
        }
        cache.set(cache_key, result, timeout=120)  # 2-minute cache for admin stats
        return result

    @staticmethod
    def get_nest_analytics(nest_id: str) -> dict:
        """Analytics for a specific Nest."""
        members = NestMembership.objects.filter(
            nest_id=nest_id, status="active"
        ).count()

        modules = ContentModule.objects.filter(nest_id=nest_id)
        total_modules = modules.count()
        published_modules = modules.filter(is_published=True).count()

        # Average completion across all members — single aggregate query
        progress_stats = ContentProgress.objects.filter(
            content_item__module__nest_id=nest_id
        ).aggregate(
            total=Count('id'),
            completed=Count('id', filter=Q(status='completed')),
        )
        completion_rate = 0
        if progress_stats['total'] > 0:
            completion_rate = round(
                (progress_stats['completed'] / progress_stats['total']) * 100, 1
            )

        total_points = PointTransaction.objects.filter(
            nest_id=nest_id
        ).aggregate(total=Sum("points"))["total"] or 0

        return {
            "active_members": members,
            "total_modules": total_modules,
            "published_modules": published_modules,
            "completion_rate": completion_rate,
            "total_points_earned": total_points,
        }

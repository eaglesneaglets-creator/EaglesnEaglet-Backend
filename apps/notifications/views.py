"""
Notification Views

API endpoints for listing, reading, and managing notifications.
"""

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from .models import NotificationPreference
from .serializers import (
    NotificationPreferenceUpdateSerializer,
    NotificationSerializer,
    build_preferences_response,
)
from .services import NotificationService


class NotificationViewSet(ViewSet):
    """
    Notification endpoints.

    GET  /notifications/           → list notifications
    GET  /notifications/unread/    → unread count
    PATCH /notifications/{id}/read/ → mark one as read
    POST /notifications/read-all/  → mark all as read
    """

    permission_classes = [IsAuthenticated]

    def list(self, request):
        """List user's notifications."""
        unread_only = request.query_params.get("unread") == "true"
        notifications = NotificationService.get_user_notifications(
            request.user, unread_only=unread_only
        )
        serializer = NotificationSerializer(notifications[:50], many=True)
        return Response({"success": True, "data": serializer.data})

    @action(detail=False, methods=["get"], url_path="unread")
    def unread_count(self, request):
        """Get count of unread notifications."""
        count = NotificationService.get_unread_count(request.user)
        return Response({"success": True, "data": {"unread_count": count}})

    @action(detail=True, methods=["patch"], url_path="read")
    def mark_read(self, request, pk=None):
        """Mark a notification as read."""
        success = NotificationService.mark_as_read(request.user, pk)
        if not success:
            return Response(
                {"success": False, "error": {"message": "Notification not found or already read."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({"success": True})

    @action(detail=False, methods=["post"], url_path="read-all")
    def mark_all_read(self, request):
        """Mark all notifications as read."""
        count = NotificationService.mark_all_as_read(request.user)
        return Response({"success": True, "data": {"marked_count": count}})


class NotificationPreferenceView(APIView):
    """
    GET   /notifications/preferences/  → registry-merged prefs grouped by domain
    PATCH /notifications/preferences/  → bulk upsert
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        data = build_preferences_response(request.user)
        return Response({"success": True, "data": data})

    def patch(self, request):
        serializer = NotificationPreferenceUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        for item in serializer.validated_data["preferences"]:
            NotificationPreference.objects.update_or_create(
                user=request.user,
                event_type=item["event_type"],
                defaults={
                    "email_enabled": item["email_enabled"],
                    "inapp_enabled": item["inapp_enabled"],
                },
            )
        data = build_preferences_response(request.user)
        return Response({"success": True, "data": data}, status=status.HTTP_200_OK)

"""
Notification Views

API endpoints for listing, reading, and managing notifications.
"""

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from .serializers import NotificationSerializer
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

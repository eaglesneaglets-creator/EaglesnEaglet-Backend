"""
Notification URL Configuration
"""

from django.urls import path

from .views import NotificationViewSet

urlpatterns = [
    path("", NotificationViewSet.as_view({"get": "list"}), name="notification-list"),
    path("unread/", NotificationViewSet.as_view({"get": "unread_count"}), name="notification-unread"),
    path("read-all/", NotificationViewSet.as_view({"post": "mark_all_read"}), name="notification-read-all"),
    path("<uuid:pk>/read/", NotificationViewSet.as_view({"patch": "mark_read"}), name="notification-mark-read"),
]

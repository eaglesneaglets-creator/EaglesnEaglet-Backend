from django.contrib import admin

from .models import Notification


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ["recipient", "notification_type", "title", "is_read", "created_at"]
    list_filter = ["notification_type", "is_read"]
    search_fields = ["recipient__email", "title", "message"]
    readonly_fields = ["id", "created_at"]

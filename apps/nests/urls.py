"""
Nest URL Configuration

Routes for Nest CRUD, memberships, requests, posts, resources, and events.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    NestViewSet,
    MembershipViewSet,
    MentorshipRequestViewSet,
    NestPostViewSet,
    NestResourceViewSet,
    NestEventViewSet,
    UploadMediaView,
)

# Top-level nest router
router = DefaultRouter()
router.register(r"", NestViewSet, basename="nest")

# Nested routes under /nests/{nest_pk}/
member_list = MembershipViewSet.as_view({"get": "list"})
member_detail = MembershipViewSet.as_view({"delete": "destroy"})

request_list = MentorshipRequestViewSet.as_view({"get": "list", "post": "create"})
request_detail = MentorshipRequestViewSet.as_view({"patch": "partial_update"})

post_list = NestPostViewSet.as_view({"get": "list", "post": "create"})
post_comment = NestPostViewSet.as_view({"post": "add_comment"})
post_like = NestPostViewSet.as_view({"post": "like"})
post_comment_list = NestPostViewSet.as_view({"get": "list_comments"})
post_reply = NestPostViewSet.as_view({"post": "add_reply"})

resource_list = NestResourceViewSet.as_view({"get": "list", "post": "create"})
event_list = NestEventViewSet.as_view({"get": "list", "post": "create"})
event_attend = NestEventViewSet.as_view({"post": "mark_attendance"})

nested_urlpatterns = [
    path("members/", member_list, name="nest-members"),
    path("members/<uuid:pk>/", member_detail, name="nest-member-detail"),
    path("requests/", request_list, name="nest-requests"),
    path("requests/<uuid:pk>/", request_detail, name="nest-request-detail"),
    path("posts/", post_list, name="nest-posts"),
    path("posts/<uuid:pk>/comments/", post_comment, name="nest-post-comments"),
    path("posts/<uuid:pk>/like/", post_like, name="nest-post-like"),
    path("posts/<uuid:pk>/comment-list/", post_comment_list, name="nest-post-comment-list"),
    path("posts/<uuid:pk>/comments/<uuid:comment_pk>/replies/", post_reply, name="nest-post-reply"),
    path("resources/", resource_list, name="nest-resources"),
    path("events/", event_list, name="nest-events"),
    path("events/<uuid:pk>/attend/", event_attend, name="nest-event-attend"),
]

urlpatterns = [
    path("", include(router.urls)),
    path("<uuid:nest_pk>/", include(nested_urlpatterns)),
    path("upload/", UploadMediaView.as_view(), name="nest-media-upload"),
]

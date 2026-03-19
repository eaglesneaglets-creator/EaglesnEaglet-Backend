"""
Content URL Configuration

Routes for content modules, items, assignments, progress, and module quizzes.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    ContentModuleViewSet,
    ContentItemViewSet,
    AssignmentViewSet,
    ProgressViewSet,
    ModuleQuizViewSet,
)

# Top-level content routes
router = DefaultRouter()
router.register(r"modules", ContentModuleViewSet, basename="module")
router.register(r"assignments", AssignmentViewSet, basename="assignment")
router.register(r"progress", ProgressViewSet, basename="progress")

# Nested item routes under /modules/{module_pk}/items/
item_list = ContentItemViewSet.as_view({"get": "list", "post": "create"})
item_detail = ContentItemViewSet.as_view({"get": "retrieve", "patch": "partial_update", "delete": "destroy"})

# Quiz routes under /modules/{module_pk}/quiz/
quiz_root = ModuleQuizViewSet.as_view({"get": "retrieve", "post": "create"})
quiz_attempt = ModuleQuizViewSet.as_view({"post": "attempt"})
quiz_attempts = ModuleQuizViewSet.as_view({"get": "attempts"})

nested_module_patterns = [
    path("items/", item_list, name="module-items"),
    path("items/<uuid:pk>/", item_detail, name="module-item-detail"),
    path("quiz/", quiz_root, name="module-quiz"),
    path("quiz/attempt/", quiz_attempt, name="module-quiz-attempt"),
    path("quiz/attempts/", quiz_attempts, name="module-quiz-attempts"),
]

urlpatterns = [
    path("", include(router.urls)),
    path("modules/<uuid:module_pk>/", include(nested_module_patterns)),
    path(
        "my-progress/",
        ProgressViewSet.as_view({"get": "summary"}),
        name="my-progress",
    ),
]

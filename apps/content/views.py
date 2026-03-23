"""
Content Views

API endpoints for learning content management, progress tracking,
and assignment submission/grading.
"""

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError

from core.pagination import StandardResultsSetPagination
from core.permissions import IsEagle

from .serializers import (
    ContentModuleListSerializer,
    ContentModuleDetailSerializer,
    ContentModuleCreateSerializer,
    ContentItemSerializer,
    ContentItemCreateSerializer,
    AssignmentSerializer,
    AssignmentCreateSerializer,
    ContentProgressSerializer,
    ProgressUpdateSerializer,
    ProgressSummarySerializer,
    AssignmentSubmissionSerializer,
    AssignmentGradeSerializer,
    ModuleAssignmentSerializer,
    ModuleAssignmentEagleSerializer,
    ModuleQuizCreateSerializer,
    ModuleAssignmentAttemptSerializer,
    QuizSubmitSerializer,
)
from .services import ContentService, ProgressService, ModuleQuizService


class ContentModuleViewSet(ViewSet):
    """
    Content module CRUD.

    GET  /content/modules/?nest={id}  → list modules
    POST /content/modules/            → create (Eagle/Admin)
    GET  /content/modules/{id}/       → detail with items
    PATCH /content/modules/{id}/      → update (Eagle/Admin)
    DELETE /content/modules/{id}/     → delete (Eagle/Admin)
    POST /content/modules/{id}/publish/ → publish (Eagle/Admin)
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def list(self, request):
        """List modules for a nest."""
        nest_id = request.query_params.get("nest")
        created_by_id = request.query_params.get("created_by")
        visibility = request.query_params.get("visibility")
        modules = ContentService.get_nest_modules(
            nest_id, request.user, created_by_id=created_by_id, visibility=visibility
        )
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(modules, request)
        serializer = ContentModuleListSerializer(page, many=True, context={"request": request})
        data = serializer.data

        # If Eaglet, inject user-specific progress in one batch (Fixes N+1)
        if request.user.role == "eaglet":
            from .services import ProgressService
            # Get progress for all modules in this page in one query
            module_ids = [m["id"] for m in data]
            progress_map = ProgressService.get_bulk_module_progress(request.user, module_ids)
            
            for module_data in data:
                stats = progress_map.get(module_data["id"], {"progress_percentage": 0, "status": "not_started"})
                module_data["progress"] = stats["progress_percentage"]
                module_data["status"] = stats["status"]

        return paginator.get_paginated_response(data)

    def create(self, request):
        """Create a module (Eagle or Admin)."""
        nest_id = request.data.get("nest") or None
        if not nest_id and request.user.role != "admin":
            return Response(
                {"success": False, "error": {"message": "nest field required for non-admin users."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = ContentModuleCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        module = ContentService.create_module(
            request.user, nest_id, serializer.validated_data
        )
        return Response(
            {"success": True, "data": ContentModuleDetailSerializer(module).data},
            status=status.HTTP_201_CREATED,
        )

    def retrieve(self, request, pk=None):
        """Get module details with items."""
        from .models import ContentModule
        try:
            module = ContentModule.objects.select_related(
                "created_by", "nest"
            ).prefetch_related("items").get(pk=pk)
        except ContentModule.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Module not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(
            {"success": True, "data": ContentModuleDetailSerializer(module).data}
        )

    def partial_update(self, request, pk=None):
        """Update a content module."""
        serializer = ContentModuleCreateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        try:
            module = ContentService.update_module(
                user=request.user, module_id=pk, data=serializer.validated_data
            )
            return Response({
                "success": True, 
                "data": ContentModuleDetailSerializer(module).data
            })
        except (NotFound, PermissionDenied, ValidationError) as e:
            return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN if isinstance(e, PermissionDenied) else status.HTTP_404_NOT_FOUND)

    def destroy(self, request, pk=None):
        """Delete a content module."""
        try:
            ContentService.delete_module(user=request.user, module_id=pk)
            return Response(status=status.HTTP_204_NO_CONTENT)
        except (NotFound, PermissionDenied) as e:
            return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN if isinstance(e, PermissionDenied) else status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        """Publish a module."""
        try:
            module = ContentService.publish_module(request.user, pk)
            return Response({
                "success": True, 
                "data": ContentModuleDetailSerializer(module).data
            })
        except (NotFound, PermissionDenied, ValidationError) as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ContentItemViewSet(ViewSet):
    """
    Content item endpoints under a module.
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def _check_module_access(self, user, module_pk):
        """Verify user has access to the module's nest."""
        from .models import ContentModule
        from apps.nests.models import NestMembership
        try:
            module = ContentModule.objects.select_related("nest").get(pk=module_pk)
        except ContentModule.DoesNotExist:
            return None, Response(
                {"success": False, "error": {"message": "Module not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        if not module.nest or user.role == "admin" or module.nest.eagle_id == user.id:
            return module, None
        if NestMembership.objects.filter(nest=module.nest, user=user, status="active").exists():
            return module, None
        return None, Response(
            {"success": False, "error": {"message": "You don't have access to this module."}},
            status=status.HTTP_403_FORBIDDEN,
        )

    def list(self, request, module_pk=None):
        """List items in a module."""
        _, error = self._check_module_access(request.user, module_pk)
        if error: return error
        items = ContentService.get_module_items(module_pk)
        serializer = ContentItemSerializer(items, many=True)
        return Response({"success": True, "data": serializer.data})

    def retrieve(self, request, module_pk=None, pk=None):
        """Get a single content item."""
        _, error = self._check_module_access(request.user, module_pk)
        if error:
            return error
        from .models import ContentItem
        try:
            item = ContentItem.objects.get(pk=pk, module_id=module_pk)
        except ContentItem.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Content item not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({"success": True, "data": ContentItemSerializer(item).data})

    def create(self, request, module_pk=None):
        """Add a content item."""
        serializer = ContentItemCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        item = ContentService.add_content_item(request.user, module_pk, serializer.validated_data)
        return Response(
            {"success": True, "data": ContentItemSerializer(item).data},
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, module_pk=None, pk=None):
        """Update a content item."""
        serializer = ContentItemCreateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        try:
            item = ContentService.update_content_item(user=request.user, item_id=pk, data=serializer.validated_data)
            return Response({"success": True, "data": ContentItemSerializer(item).data})
        except (NotFound, PermissionDenied, ValidationError) as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, module_pk=None, pk=None):
        """Delete a content item."""
        try:
            ContentService.delete_content_item(user=request.user, item_id=pk)
            return Response(status=status.HTTP_204_NO_CONTENT)
        except (NotFound, PermissionDenied) as e:
            return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN if isinstance(e, PermissionDenied) else status.HTTP_404_NOT_FOUND)


class AssignmentViewSet(ViewSet):
    """
    Assignment endpoints.
    """

    permission_classes = [IsAuthenticated]

    def list(self, request):
        """List assignments.

        Filters:
          ?nest=<id>             — all assignments for a specific nest
          ?module=<id>           — assignments for a specific module
          ?assignment_type=      — filter by type (standalone, etc.)
          ?my_assignments=true   — eaglet shortcut: all standalone assignments
                                   across every nest the current user belongs to
        """
        from .models import Assignment
        nest_id = request.query_params.get("nest")
        module_id = request.query_params.get("module")
        assignment_type = request.query_params.get("assignment_type")
        my_assignments = request.query_params.get("my_assignments")

        if my_assignments:
            from apps.nests.models import NestMembership
            nest_ids = NestMembership.objects.filter(
                user=request.user, status="active"
            ).values_list("nest_id", flat=True)
            qs = Assignment.objects.filter(
                nest_id__in=nest_ids,
                assignment_type="standalone",
            ).order_by("-created_at")
            serializer = AssignmentSerializer(qs, many=True, context={"request": request})
            return Response({"success": True, "data": serializer.data})

        if not nest_id and not module_id:
            return Response(
                {"success": False, "error": {"message": "nest or module query param required."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = Assignment.objects.all()
        if nest_id:
            qs = qs.filter(nest_id=nest_id)
        if module_id:
            qs = qs.filter(module_id=module_id)
        if assignment_type:
            qs = qs.filter(assignment_type=assignment_type)

        serializer = AssignmentSerializer(qs, many=True, context={"request": request})
        return Response({"success": True, "data": serializer.data})

    def retrieve(self, request, pk=None):
        """Get a single assignment."""
        from .models import Assignment
        try:
            assignment = Assignment.objects.get(pk=pk)
        except Assignment.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Assignment not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({"success": True, "data": AssignmentSerializer(assignment, context={"request": request}).data})

    def partial_update(self, request, pk=None):
        """Update an assignment (Eagle only)."""
        from .models import Assignment
        try:
            assignment = Assignment.objects.get(pk=pk)
        except Assignment.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Assignment not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = AssignmentSerializer(assignment, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"success": True, "data": serializer.data})

    def create(self, request):
        """Create a standalone assignment (Eagle only). Requires nest_id."""
        serializer = AssignmentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        nest_id = data.pop("nest_id", None) or request.data.get("nest_id")
        if not nest_id:
            return Response(
                {"success": False, "error": {"message": "nest_id field required."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        file = request.FILES.get("file")
        assignment = ContentService.create_standalone_assignment(
            request.user, str(nest_id), data, file=file
        )
        return Response(
            {"success": True, "data": AssignmentSerializer(assignment, context={"request": request}).data},
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"])
    def submit(self, request, pk=None):
        """Eaglet submits work for an assignment."""
        file = request.FILES.get("file")
        notes = request.data.get("notes", "")

        if not file:
            raise ValidationError({"file": "A file is required to submit this assignment."})

        # Upload to Cloudinary and get the secure URL
        from core.storage import upload_to_cloudinary
        result = upload_to_cloudinary(file, file_type="misc")
        file_url = result.get("secure_url") or result.get("url")

        submission = ProgressService.submit_assignment(
            request.user, pk, {"file_url": file_url, "notes": notes}
        )
        return Response(
            {"success": True, "data": AssignmentSubmissionSerializer(submission).data},
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["patch"], url_path="grade/(?P<submission_pk>[^/.]+)")
    def grade(self, request, pk=None, submission_pk=None):
        """Eagle grades a submission."""
        serializer = AssignmentGradeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        submission = ProgressService.grade_submission(
            request.user,
            submission_pk,
            serializer.validated_data["grade"],
            serializer.validated_data.get("feedback", ""),
        )
        return Response(
            {"success": True, "data": AssignmentSubmissionSerializer(submission).data}
        )

    @action(detail=False, methods=["get"])
    def submissions(self, request):
        """Mentor lists all submissions for their nest(s)."""
        nest_id = request.query_params.get("nest")
        submission_status = request.query_params.get("status")
        submissions = ProgressService.get_mentor_submissions(
            request.user, nest_id, submission_status
        )
        serializer = AssignmentSubmissionSerializer(submissions, many=True)
        return Response({"success": True, "data": serializer.data})


class ProgressViewSet(ViewSet):
    """
    Progress tracking endpoints.
    """

    permission_classes = [IsAuthenticated]

    def list(self, request):
        """List user's content progress."""
        nest_id = request.query_params.get("nest")
        progress = ProgressService.get_user_progress(request.user, nest_id)
        serializer = ContentProgressSerializer(progress, many=True)
        return Response({"success": True, "data": serializer.data})

    def partial_update(self, request, pk=None):
        """Update progress on a content item."""
        serializer = ProgressUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        progress = ProgressService.update_progress(
            request.user,
            pk,
            serializer.validated_data["progress_percentage"],
            serializer.validated_data.get("watch_duration_seconds", 0),
        )
        return Response(
            {"success": True, "data": ContentProgressSerializer(progress).data}
        )

    @action(detail=False, methods=["get"], url_path="summary")
    def summary(self, request):
        """Get progress summary for dashboard."""
        summary = ProgressService.get_user_progress_summary(request.user)
        serializer = ProgressSummarySerializer(summary)
        return Response({"success": True, "data": serializer.data})


class ModuleQuizViewSet(ViewSet):
    """
    Quiz endpoints nested under a module.

    GET  /content/modules/{module_pk}/quiz/            → get quiz
    POST /content/modules/{module_pk}/quiz/            → create/replace quiz (Eagle)
    POST /content/modules/{module_pk}/quiz/attempt/    → submit attempt (Eaglet)
    GET  /content/modules/{module_pk}/quiz/attempts/   → attempt history (Eaglet)
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def _get_module(self, module_pk):
        from .models import ContentModule
        try:
            return ContentModule.objects.select_related("nest").get(pk=module_pk)
        except ContentModule.DoesNotExist:
            raise NotFound("Module not found.")

    def retrieve(self, request, module_pk=None):
        """Get the quiz for a module."""
        module = self._get_module(module_pk)
        is_eagle = request.user.role in ("eagle", "admin")
        if is_eagle and (module.nest is None or module.nest.eagle_id == request.user.id or request.user.role == "admin"):
            quiz = ModuleQuizService.get_quiz_for_eagle(module_pk)
            return Response({"success": True, "data": ModuleAssignmentEagleSerializer(quiz).data})
        quiz, attempts_used = ModuleQuizService.get_quiz_for_eaglet(module_pk, request.user)
        data = ModuleAssignmentSerializer(quiz).data
        data["attempts_used"] = attempts_used
        data["attempts_remaining"] = quiz.max_attempts - attempts_used
        return Response({"success": True, "data": data})

    def create(self, request, module_pk=None):
        """Eagle creates or replaces the quiz for a module."""
        module = self._get_module(module_pk)
        if request.user.role not in ("eagle", "admin"):
            raise PermissionDenied("Only Eagles can create quizzes.")
        if module.nest and module.nest.eagle_id != request.user.id and request.user.role != "admin":
            raise PermissionDenied("Only the Nest owner can manage this quiz.")

        serializer = ModuleQuizCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        questions_data = serializer.validated_data.pop("questions")
        quiz = ModuleQuizService.create_quiz(module, serializer.validated_data, questions_data)
        return Response(
            {"success": True, "data": ModuleAssignmentEagleSerializer(quiz).data},
            status=status.HTTP_201_CREATED,
        )

    def attempt(self, request, module_pk=None):
        """Eaglet submits a quiz attempt."""
        from .models import ModuleAssignment
        try:
            quiz = ModuleAssignment.objects.get(module_id=module_pk)
        except ModuleAssignment.DoesNotExist:
            raise NotFound("This module has no quiz.")

        serializer = QuizSubmitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = ModuleQuizService.submit_attempt(
            quiz.id, request.user, serializer.validated_data["answers"]
        )
        return Response({"success": True, "data": result}, status=status.HTTP_201_CREATED)

    def attempts(self, request, module_pk=None):
        """Get current user's attempt history for this module's quiz."""
        from .models import ModuleAssignment, ModuleAssignmentAttempt
        try:
            quiz = ModuleAssignment.objects.get(module_id=module_pk)
        except ModuleAssignment.DoesNotExist:
            raise NotFound("This module has no quiz.")

        quiz_attempts = ModuleAssignmentAttempt.objects.filter(
            assignment=quiz, user=request.user
        )
        serializer = ModuleAssignmentAttemptSerializer(quiz_attempts, many=True)
        return Response({"success": True, "data": serializer.data})

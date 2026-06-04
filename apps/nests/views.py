"""
Nest Views

API endpoints for Nest CRUD, membership management, community features
(posts, resources, events), and mentorship requests.
"""

from django.db.models import Count, Q, ExpressionWrapper, BooleanField, F
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from core.pagination import StandardResultsSetPagination
from core.permissions import IsEagleOrAdmin, IsNestMember, IsNestOwnerFromURL

from .serializers import (
    NestListSerializer,
    NestDetailSerializer,
    NestCreateSerializer,
    MembershipSerializer,
    MentorshipRequestSerializer,
    NestPostSerializer,
    NestPostCreateSerializer,
    NestResourceSerializer,
    NestResourceCreateSerializer,
    NestEventSerializer,
    NestEventCreateSerializer,
)
from .permissions import HasActiveProgram, IsPlatformAdmin
from .services import NestService, MembershipService, CommunityService


def _annotate_nest_counts(queryset):
    """Annotate a Nest queryset with member_count and is_full (reused by list & retrieve)."""
    return queryset.annotate(
        annotated_member_count=Count(
            'memberships',
            filter=Q(memberships__status='active') & ~Q(memberships__user=F('eagle'))
        )
    ).annotate(
        annotated_is_full=ExpressionWrapper(
            Q(annotated_member_count__gte=F('max_members')),
            output_field=BooleanField()
        )
    )


class NestViewSet(ViewSet):
    """
    Nest CRUD operations.

    GET  /nests/           → list (public + user's)
    POST /nests/           → create (Eagle only)
    GET  /nests/{id}/      → detail
    PATCH /nests/{id}/     → update (owner only)
    DELETE /nests/{id}/    → soft-delete (owner only)
    GET  /nests/joined/    → nests the user is an active member of (eaglet)
    GET  /nests/owned/     → nests the user owns (eagle)
    GET  /nests/my/        → DEPRECATED alias for /nests/joined/. Remove next
                             release once all clients migrate.
    """

    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def list(self, request):
        """List public nests; Eagles see their own too."""
        if request.user.role == "eagle":
            nests = NestService.get_eagle_nests(request.user)
        else:
            nests = NestService.get_public_nests()

        # Fix N+1: Annotate member_count and is_full
        nests = _annotate_nest_counts(nests)

        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(nests, request)
        serializer = NestListSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def create(self, request):
        """Create a new Nest (Eagle only)."""
        self.check_permissions(request)
        if request.user.role != "eagle":
            return Response(
                {"success": False, "error": {"message": "Only Eagles can create Nests."}},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = NestCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        nest = NestService.create_nest(request.user, serializer.validated_data)
        return Response(
            {"success": True, "data": NestDetailSerializer(nest).data},
            status=status.HTTP_201_CREATED,
        )

    def retrieve(self, request, pk=None):
        """Retrieve nest details."""
        from .models import Nest
        try:
            nest = _annotate_nest_counts(
                Nest.objects.select_related("eagle")
                .prefetch_related("programs__objectives__rules")
            ).get(pk=pk)
        except Nest.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Nest not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(
            {"success": True, "data": NestDetailSerializer(nest).data}
        )

    def partial_update(self, request, pk=None):
        """Update a Nest (owner only)."""
        from .models import Nest
        try:
            nest = Nest.objects.get(pk=pk)
        except Nest.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Nest not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        # SECURITY: Only the nest owner (eagle) may update it. Admins bypass this check.
        if request.user.role != 'admin' and nest.eagle_id != request.user.id:
            return Response(
                {"success": False, "error": {"message": "Only the Nest owner can update it."}},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = NestCreateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        nest = NestService.update_nest(nest, request.user, serializer.validated_data)
        return Response(
            {"success": True, "data": NestDetailSerializer(nest).data}
        )

    def destroy(self, request, pk=None):
        """Soft-delete a Nest (owner only)."""
        from .models import Nest
        try:
            nest = Nest.objects.get(pk=pk)
        except Nest.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Nest not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        if nest.eagle_id != request.user.id:
            return Response(
                {"success": False, "error": {"message": "Only the Nest owner can delete it."}},
                status=status.HTTP_403_FORBIDDEN,
            )

        nest.soft_delete()
        return Response(
            {"success": True, "data": {"message": "Nest deleted."}},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["get"], url_path="eaglets",
            permission_classes=[IsAuthenticated, IsEagleOrAdmin])
    def eaglets(self, request, pk=None):
        """List active Eaglets in this Nest (for the award points modal dropdown)."""
        from .models import Nest, NestMembership
        try:
            nest = Nest.objects.get(pk=pk)
        except Nest.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Nest not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Eagles can only see eaglets in their own nests; admins see all
        if request.user.role == "eagle" and nest.eagle != request.user:
            return Response(
                {"success": False, "error": {"message": "You do not own this Nest."}},
                status=status.HTTP_403_FORBIDDEN,
            )

        memberships = (
            NestMembership.objects
            .filter(nest=nest, status="active")
            .exclude(user=nest.eagle)
            .select_related("user")
        )
        data = [
            {
                "id": str(m.user.id),
                "first_name": m.user.first_name,
                "last_name": m.user.last_name,
                "full_name": m.user.full_name,
                "email": m.user.email,
                "avatar_url": (
                    m.user.avatar.url
                    if m.user.avatar
                    else m.user.profile_picture_url or None
                ),
            }
            for m in memberships
        ]
        return Response({"success": True, "data": data})

    @action(detail=False, methods=["get"], url_path="joined")
    def joined_nests(self, request):
        """Nests where the current user is an active member (eaglet view)."""
        nests = NestService.get_eaglet_nests(request.user)
        serializer = NestListSerializer(nests, many=True)
        return Response({"success": True, "data": serializer.data})

    @action(detail=False, methods=["get"], url_path="owned")
    def owned_nests(self, request):
        """Nests where the current user is the eagle owner (mentor view)."""
        nests = NestService.get_eagle_nests(request.user)
        serializer = NestListSerializer(nests, many=True)
        return Response({"success": True, "data": serializer.data})

    @action(detail=False, methods=["get"], url_path="my")
    def my_nests(self, request):
        """DEPRECATED — alias of /nests/joined/. Kept for back-compat."""
        return self.joined_nests(request)

    @action(detail=False, methods=["get"], url_path="my-requests")
    def my_requests(self, request):
        """List current mentorship requests for the logged-in user."""
        requests = MembershipService.get_eaglet_requests(request.user)
        serializer = MentorshipRequestSerializer(requests, many=True)
        return Response({"success": True, "data": serializer.data})


class MembershipViewSet(ViewSet):
    """
    Nest membership endpoints.

    GET    /nests/{nest_pk}/members/           → list members (members only)
    DELETE /nests/{nest_pk}/members/{pk}/      → remove member (Eagle)
    """

    permission_classes = [IsAuthenticated, IsNestMember]

    def list(self, request, nest_pk=None):
        """List active members of a Nest."""
        members = MembershipService.get_nest_members(nest_pk)
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(members, request)
        serializer = MembershipSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def destroy(self, request, nest_pk=None, pk=None):
        """Remove a member from a Nest (Eagle only)."""
        membership = MembershipService.remove_member(request.user, pk)
        return Response(
            {"success": True, "data": MembershipSerializer(membership).data}
        )


class MentorshipRequestViewSet(ViewSet):
    """
    Mentorship request endpoints.

    GET  /nests/{nest_pk}/requests/            → list pending (Nest owner only)
    POST /nests/{nest_pk}/requests/            → create request (Eaglet)
    PATCH /nests/{nest_pk}/requests/{pk}/      → approve/reject (Eagle)
    """

    permission_classes = [IsAuthenticated]

    def list(self, request, nest_pk=None):
        """List pending requests for a Nest (Nest owner only)."""
        self.permission_classes = [IsAuthenticated, IsNestOwnerFromURL]
        self.check_permissions(request)

        requests = MembershipService.get_pending_requests(nest_pk)
        serializer = MentorshipRequestSerializer(requests, many=True)
        return Response({"success": True, "data": serializer.data})

    def create(self, request, nest_pk=None):
        """Plan 14.6-01: retired. Use POST /nests/{nest_pk}/enroll/ instead."""
        return Response(
            {
                "success": False,
                "error": {
                    "code": "LegacyJoinFlowRetired",
                    "message": (
                        "This join flow has been retired. "
                        "Use POST /nests/{nest_id}/enroll/ instead."
                    ),
                    "migration_endpoint": f"/nests/{nest_pk}/enroll/",
                },
            },
            status=status.HTTP_410_GONE,
        )

    def partial_update(self, request, nest_pk=None, pk=None):
        """Plan 14.6-01: retired. Approve/reject happens on ProgramEnrollment."""
        return Response(
            {
                "success": False,
                "error": {
                    "code": "LegacyJoinFlowRetired",
                    "message": (
                        "Approval of legacy mentorship requests is retired. "
                        "Manage approvals on /program-enrollments/{id}/."
                    ),
                    "migration_endpoint": "/program-enrollments/",
                },
            },
            status=status.HTTP_410_GONE,
        )


class NestPostViewSet(ViewSet):
    """Nest post feed endpoints."""

    permission_classes = [IsAuthenticated, IsNestMember]

    def list(self, request, nest_pk=None):
        """List posts in a Nest."""
        posts = CommunityService.get_nest_posts(nest_pk)
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(posts, request)
        serializer = NestPostSerializer(page, many=True, context={"request": request})
        return paginator.get_paginated_response(serializer.data)

    def create(self, request, nest_pk=None):
        """Create a post in a Nest."""
        serializer = NestPostCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        post = CommunityService.create_post(
            request.user, nest_pk, serializer.validated_data
        )
        return Response(
            {"success": True, "data": NestPostSerializer(post).data},
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], url_path="comments")
    def add_comment(self, request, nest_pk=None, pk=None):
        """Add a comment to a post."""
        content = request.data.get("content", "").strip()
        if not content:
            return Response(
                {"success": False, "error": {"message": "Content is required."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from .serializers import NestPostCommentSerializer
        comment = CommunityService.add_comment(request.user, pk, content)
        return Response(
            {"success": True, "data": NestPostCommentSerializer(comment).data},
            status=status.HTTP_201_CREATED,
        )

    def like(self, request, nest_pk=None, pk=None):
        """Toggle like on a post. Returns { liked, likes_count }."""
        from .serializers import NestPostLikeToggleResponseSerializer
        result = CommunityService.toggle_like(pk, request.user)
        return Response(NestPostLikeToggleResponseSerializer(result).data)

    def list_comments(self, request, nest_pk=None, pk=None):
        """List top-level comments with replies for a post."""
        from .serializers import NestPostCommentSerializer
        comments = CommunityService.get_comments(pk)
        return Response(NestPostCommentSerializer(comments, many=True).data)

    def add_reply(self, request, nest_pk=None, pk=None, comment_pk=None):
        """Add a reply to a comment."""
        content = request.data.get("content", "").strip()
        if not content:
            return Response(
                {"success": False, "error": {"message": "Content is required."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        from .serializers import ReplySerializer
        reply = CommunityService.add_reply(comment_pk, request.user, content)
        return Response(
            {"success": True, "data": ReplySerializer(reply).data},
            status=status.HTTP_201_CREATED,
        )


class NestResourceViewSet(ViewSet):
    """Nest shared library endpoints."""

    permission_classes = [IsAuthenticated, IsNestMember, HasActiveProgram]

    def list(self, request, nest_pk=None):
        """List resources in a Nest."""
        resources = CommunityService.get_nest_resources(nest_pk)
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(resources, request)
        serializer = NestResourceSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def create(self, request, nest_pk=None):
        """Upload a resource to a Nest."""
        serializer = NestResourceCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        resource = CommunityService.upload_resource(
            request.user, nest_pk, serializer.validated_data
        )
        return Response(
            {"success": True, "data": NestResourceSerializer(resource).data},
            status=status.HTTP_201_CREATED,
        )


class NestEventViewSet(ViewSet):
    """Nest event endpoints."""

    permission_classes = [IsAuthenticated, IsNestMember]

    def list(self, request, nest_pk=None):
        """List upcoming events in a Nest."""
        events = CommunityService.get_nest_events(nest_pk)
        serializer = NestEventSerializer(events, many=True)
        return Response({"success": True, "data": serializer.data})

    def create(self, request, nest_pk=None):
        """Create an event in a Nest (Eagle only)."""
        serializer = NestEventCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        event = CommunityService.create_event(
            request.user, nest_pk, serializer.validated_data
        )
        return Response(
            {"success": True, "data": NestEventSerializer(event).data},
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], url_path="attend")
    def mark_attendance(self, request, nest_pk=None, pk=None):
        """Mark attendance at a Nest event. Eaglets earn points."""
        attendance = CommunityService.mark_attendance(request.user, pk)
        return Response({
            "success": True,
            "data": {
                "event_id": str(attendance.event_id),
                "attended_at": attendance.attended_at.isoformat(),
            },
        }, status=status.HTTP_201_CREATED)


class UploadMediaView(APIView):
    """Upload a file to Cloudinary. Returns { url, type }."""

    permission_classes = [IsAuthenticated]
    MAX_UPLOAD_SIZE = 52_428_800  # 50 MB

    def post(self, request):
        file = request.FILES.get("file")
        if not file:
            return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
        if file.size > self.MAX_UPLOAD_SIZE:
            return Response({"error": "File too large. Max 50 MB."}, status=status.HTTP_400_BAD_REQUEST)

        from core.storage import upload_to_cloudinary
        try:
            result = upload_to_cloudinary(file, file_type="misc")
        except Exception:
            return Response(
                {"error": "Upload failed. Please try again."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        cloudinary_type = result.get("resource_type", "raw")
        media_type = "image" if cloudinary_type == "image" else "video" if cloudinary_type == "video" else "file"

        from .serializers import MediaUploadResponseSerializer
        return Response(
            MediaUploadResponseSerializer({"url": result["secure_url"], "type": media_type}).data,
            status=status.HTTP_201_CREATED,
        )


# ===========================================================================
# Program admin viewsets (plan 14-01)
#
# Permission model: nest owner OR platform staff. Mentee-facing program
# discovery + enrollment endpoints arrive in plan 14-02.
# ===========================================================================

from django.utils import timezone
from rest_framework.viewsets import ModelViewSet

from .models_program import Program, ProgramObjective, ProgramObjectiveRule
from .permissions import IsProgramAdmin, ProgramRulesLocked
from .serializers import (
    ProgramSerializer,
    ProgramWriteSerializer,
    ProgramObjectiveSerializer,
    ProgramObjectiveRuleSerializer,
)


class ProgramViewSet(ModelViewSet):
    """CRUD for Program. Eagles see only their nests; staff see all."""

    queryset = (
        Program.objects.select_related("nest")
        .prefetch_related("objectives__rules")
        .order_by("-created_at")
    )
    permission_classes = [IsProgramAdmin]

    def get_serializer_class(self):
        if self.action in {"create", "update", "partial_update"}:
            return ProgramWriteSerializer
        return ProgramSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if not self.request.user.is_staff:
            qs = qs.filter(nest__eagle=self.request.user)
        # Plan 14.5-01: honor ?nest=<uuid> filter for FE single-program lookups.
        nest_param = self.request.query_params.get("nest")
        if nest_param:
            import uuid as _uuid
            try:
                _uuid.UUID(str(nest_param))
                qs = qs.filter(nest_id=nest_param)
            except (ValueError, TypeError):
                qs = qs.none()
        return qs

    def perform_create(self, serializer):
        nest = serializer.validated_data.get("nest")
        if nest is not None and not self.request.user.is_staff and nest.eagle_id != self.request.user.id:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You can only create programs for nests you own.")
        # Plan 14.5-01: enforce single-active-per-nest invariant at write time.
        new_status = serializer.validated_data.get("status", "draft")
        if new_status == Program.Status.ACTIVE and nest is not None:
            existing = Program.objects.filter(nest=nest, status=Program.Status.ACTIVE).exists()
            if existing:
                from rest_framework.exceptions import ValidationError
                raise ValidationError({
                    "status": "ActiveProgramExists: This nest already has an active program. Archive the current one before activating another.",
                })
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        instance = serializer.instance
        new_status = serializer.validated_data.get("status", instance.status)
        timestamps = {}
        if new_status == Program.Status.ACTIVE and instance.status != Program.Status.ACTIVE:
            timestamps["activated_at"] = timezone.now()
        if new_status == Program.Status.ARCHIVED and instance.status != Program.Status.ARCHIVED:
            timestamps["archived_at"] = timezone.now()
        serializer.save(**timestamps)


class ProgramObjectiveViewSet(ModelViewSet):
    """CRUD for objectives nested under a Program."""

    serializer_class = ProgramObjectiveSerializer
    permission_classes = [IsProgramAdmin, ProgramRulesLocked]

    def get_queryset(self):
        program_id = self.kwargs["program_pk"]
        qs = ProgramObjective.objects.filter(program_id=program_id).prefetch_related("rules")
        if not self.request.user.is_staff:
            qs = qs.filter(program__nest__eagle=self.request.user)
        return qs

    def perform_create(self, serializer):
        program_id = self.kwargs["program_pk"]
        program = Program.objects.select_related("nest").get(pk=program_id)
        if not self.request.user.is_staff and program.nest.eagle_id != self.request.user.id:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Cannot add objectives to a program you do not own.")
        serializer.save(program=program)


class ProgramObjectiveRuleViewSet(ModelViewSet):
    """CRUD for rules nested under a ProgramObjective."""

    serializer_class = ProgramObjectiveRuleSerializer
    permission_classes = [IsProgramAdmin, ProgramRulesLocked]

    def get_queryset(self):
        objective_id = self.kwargs["objective_pk"]
        qs = ProgramObjectiveRule.objects.filter(objective_id=objective_id)
        if not self.request.user.is_staff:
            qs = qs.filter(objective__program__nest__eagle=self.request.user)
        return qs

    def perform_create(self, serializer):
        objective_id = self.kwargs["objective_pk"]
        objective = ProgramObjective.objects.select_related("program__nest").get(pk=objective_id)
        if not self.request.user.is_staff and objective.program.nest.eagle_id != self.request.user.id:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Cannot add rules to an objective you do not own.")
        serializer.save(objective=objective)


# ===========================================================================
# Program enrollment views (plan 14-02)
# ===========================================================================

from rest_framework.exceptions import PermissionDenied as DRFPermissionDenied

from .models_program import ProgramEnrollment, ProgramExitRequest
from .permissions import IsEnrollmentParticipant
from .serializers import (
    ProgramEnrollmentSerializer,
    ProgramApplyInputSerializer,
    ProgramEnrollmentDecisionInputSerializer,
    ProgramExitRequestInputSerializer,
    ProgramExitDecisionInputSerializer,
    ProgramExitRequestSerializer,
)
from .services import (
    EnrollmentService,
    EnrollmentError,
)


def _enrollment_error_response(exc: EnrollmentError):
    """Map EnrollmentError → 400 with machine-readable code."""
    return Response(
        {
            "success": False,
            "error": {
                "type": exc.__class__.__name__,
                "code": exc.error_code,
                "message": str(exc),
            },
        },
        status=status.HTTP_400_BAD_REQUEST,
    )


class NestEnrollmentView(APIView):
    """POST /api/v1/nests/{nest_pk}/enroll/ — mentee applies to nest's active program."""

    permission_classes = [IsAuthenticated]

    def post(self, request, nest_pk=None):
        from .models import Nest
        try:
            nest = Nest.objects.get(pk=nest_pk, is_active=True)
        except Nest.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Nest not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ProgramApplyInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            enrollment = EnrollmentService.apply(
                mentee=request.user,
                nest=nest,
                message=serializer.validated_data.get("message", ""),
            )
        except EnrollmentError as exc:
            return _enrollment_error_response(exc)
        except DRFPermissionDenied as exc:
            return Response(
                {"success": False, "error": {"message": str(exc)}},
                status=status.HTTP_403_FORBIDDEN,
            )

        return Response(
            {"success": True, "data": ProgramEnrollmentSerializer(enrollment).data},
            status=status.HTTP_201_CREATED,
        )


class ProgramEnrollmentViewSet(ViewSet):
    """
    /api/v1/program-enrollments/ — list / retrieve enrollments.
    Custom actions: approve, reject, release, complete, opt-out-request.
    """

    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def _get_obj(self, pk):
        return (
            ProgramEnrollment.objects
            .select_related("program__nest", "mentee")
            .get(pk=pk)
        )

    def list(self, request):
        """Mentor/staff view of enrollments. Filters: ?nest, ?status."""
        if request.user.role not in {"eagle", "admin"} and not request.user.is_staff:
            return Response(
                {"success": False, "error": {"message": "Forbidden."}},
                status=status.HTTP_403_FORBIDDEN,
            )

        qs = (
            ProgramEnrollment.objects
            .select_related("program__nest", "mentee")
            .order_by("-requested_at")
        )
        if not request.user.is_staff:
            qs = qs.filter(program__nest__eagle=request.user)

        nest_id = request.query_params.get("nest")
        if nest_id:
            qs = qs.filter(program__nest_id=nest_id)
        status_q = request.query_params.get("status")
        if status_q:
            qs = qs.filter(status=status_q)

        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = ProgramEnrollmentSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def retrieve(self, request, pk=None):
        try:
            enrollment = self._get_obj(pk)
        except ProgramEnrollment.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Enrollment not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Object permission check
        if not IsEnrollmentParticipant().has_object_permission(request, self, enrollment):
            return Response(
                {"success": False, "error": {"message": "Forbidden."}},
                status=status.HTTP_403_FORBIDDEN,
            )
        return Response(
            {"success": True, "data": ProgramEnrollmentSerializer(enrollment).data}
        )

    @action(detail=False, methods=["get"], url_path="my-active")
    def my_active(self, request):
        """Mentee's currently active enrollment, if any."""
        enrollment = (
            ProgramEnrollment.objects
            .filter(mentee=request.user, status=ProgramEnrollment.Status.ACTIVE)
            .select_related("program__nest")
            .first()
        )
        if not enrollment:
            return Response(
                {"success": True, "data": None}
            )
        return Response(
            {"success": True, "data": ProgramEnrollmentSerializer(enrollment).data}
        )

    @action(detail=False, methods=["get"], url_path="my-requests")
    def my_requests(self, request):
        """Mentee's enrollment history (all statuses), newest first."""
        qs = (
            ProgramEnrollment.objects
            .filter(mentee=request.user)
            .select_related("program__nest")
            .order_by("-requested_at")
        )
        serializer = ProgramEnrollmentSerializer(qs, many=True)
        return Response({"success": True, "data": serializer.data})

    def _admin_action(self, request, pk, service_call, success_status=status.HTTP_200_OK):
        try:
            enrollment = self._get_obj(pk)
        except ProgramEnrollment.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Enrollment not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Mentor or staff only
        if not request.user.is_staff and enrollment.program.nest.eagle_id != request.user.id:
            return Response(
                {"success": False, "error": {"message": "Forbidden."}},
                status=status.HTTP_403_FORBIDDEN,
            )
        try:
            result = service_call(enrollment)
        except EnrollmentError as exc:
            return _enrollment_error_response(exc)
        return Response(
            {"success": True, "data": ProgramEnrollmentSerializer(result).data},
            status=success_status,
        )

    @action(detail=True, methods=["post"], url_path="approve")
    def approve(self, request, pk=None):
        return self._admin_action(
            request, pk,
            lambda e: EnrollmentService.approve(enrollment_id=e.id, reviewer=request.user),
        )

    @action(detail=True, methods=["post"], url_path="reject")
    def reject(self, request, pk=None):
        serializer = ProgramEnrollmentDecisionInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reason = serializer.validated_data.get("reason", "")
        return self._admin_action(
            request, pk,
            lambda e: EnrollmentService.reject(
                enrollment_id=e.id, reviewer=request.user, reason=reason,
            ),
        )

    @action(detail=True, methods=["post"], url_path="release")
    def release(self, request, pk=None):
        serializer = ProgramEnrollmentDecisionInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reason = serializer.validated_data.get("reason", "")
        return self._admin_action(
            request, pk,
            lambda e: EnrollmentService.release(
                enrollment_id=e.id, actor=request.user, reason=reason,
            ),
        )

    @action(detail=True, methods=["post"], url_path="complete")
    def complete(self, request, pk=None):
        force = (
            str(request.query_params.get("force", "")).lower() in ("true", "1", "yes")
            and request.user.is_staff
        )
        return self._admin_action(
            request, pk,
            lambda e: EnrollmentService.complete(
                enrollment_id=e.id, actor=request.user, force=force,
            ),
        )

    @action(detail=True, methods=["post"], url_path="opt-out-request")
    def opt_out_request(self, request, pk=None):
        try:
            enrollment = self._get_obj(pk)
        except ProgramEnrollment.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Enrollment not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        if enrollment.mentee_id != request.user.id:
            return Response(
                {"success": False, "error": {"message": "Only the mentee can opt out."}},
                status=status.HTTP_403_FORBIDDEN,
            )
        serializer = ProgramExitRequestInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            exit_req = EnrollmentService.request_opt_out(
                enrollment_id=enrollment.id,
                mentee=request.user,
                reason=serializer.validated_data["reason"],
            )
        except EnrollmentError as exc:
            return _enrollment_error_response(exc)
        return Response(
            {"success": True, "data": ProgramExitRequestSerializer(exit_req).data},
            status=status.HTTP_201_CREATED,
        )


class ProgramExitRequestViewSet(ViewSet):
    """/api/v1/program-exit-requests/ — mentor reviews + decides exits."""

    permission_classes = [IsAuthenticated]

    def list(self, request):
        if request.user.role not in {"eagle", "admin"} and not request.user.is_staff:
            return Response(
                {"success": False, "error": {"message": "Forbidden."}},
                status=status.HTTP_403_FORBIDDEN,
            )
        qs = (
            ProgramExitRequest.objects
            .select_related("enrollment__program__nest", "requested_by")
            .order_by("-created_at")
        )
        if not request.user.is_staff:
            qs = qs.filter(enrollment__program__nest__eagle=request.user)
        status_q = request.query_params.get("status")
        if status_q:
            qs = qs.filter(status=status_q)
        serializer = ProgramExitRequestSerializer(qs, many=True)
        return Response({"success": True, "data": serializer.data})

    @action(detail=True, methods=["post"], url_path="decide")
    def decide(self, request, pk=None):
        try:
            exit_req = (
                ProgramExitRequest.objects
                .select_related("enrollment__program__nest")
                .get(pk=pk)
            )
        except ProgramExitRequest.DoesNotExist:
            return Response(
                {"success": False, "error": {"message": "Exit request not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )
        if not request.user.is_staff and exit_req.enrollment.program.nest.eagle_id != request.user.id:
            return Response(
                {"success": False, "error": {"message": "Forbidden."}},
                status=status.HTTP_403_FORBIDDEN,
            )
        serializer = ProgramExitDecisionInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            updated = EnrollmentService.decide_opt_out(
                exit_request_id=exit_req.id,
                decider=request.user,
                approve=serializer.validated_data["approve"],
                note=serializer.validated_data.get("note", ""),
            )
        except EnrollmentError as exc:
            return _enrollment_error_response(exc)
        return Response(
            {"success": True, "data": ProgramExitRequestSerializer(updated).data}
        )


class MenteeLevelConfigViewSet(ViewSet):
    """
    Admin CRUD for the 5 MenteeLevelConfig rows (plan 14-04).

    GET   /api/v1/admin/mentee-levels/  → list all 5 rows ordered by level
    PATCH /api/v1/admin/mentee-levels/  → bulk-update thresholds/names/descriptions

    Locked: cannot create/delete rows (fixed 5 tiers); cannot disable
    `unlocks_mentor_application` on level 5; points_required must stay
    monotonically non-decreasing across levels.
    """

    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def list(self, request):
        from .models_program import MenteeLevelConfig
        from .serializers import MenteeLevelConfigSerializer
        qs = MenteeLevelConfig.objects.order_by("level")
        return Response(
            {"success": True, "data": MenteeLevelConfigSerializer(qs, many=True).data}
        )

    @action(detail=False, methods=["patch"], url_path="bulk-update")
    def bulk_update(self, request):
        from django.db import transaction
        from .models_program import MenteeLevelConfig
        from .serializers import (
            MenteeLevelConfigBulkUpdateSerializer,
            MenteeLevelConfigSerializer,
        )
        payload = MenteeLevelConfigBulkUpdateSerializer(data=request.data)
        payload.is_valid(raise_exception=True)
        editable = {"name", "points_required", "description"}
        with transaction.atomic():
            for row in payload.validated_data["levels"]:
                level = row["level"]
                updates = {k: v for k, v in row.items() if k in editable}
                if updates:
                    MenteeLevelConfig.objects.filter(level=level).update(**updates)
        qs = MenteeLevelConfig.objects.order_by("level")
        return Response(
            {"success": True, "data": MenteeLevelConfigSerializer(qs, many=True).data}
        )

    def partial_update(self, request, pk=None):
        return self.bulk_update(request)

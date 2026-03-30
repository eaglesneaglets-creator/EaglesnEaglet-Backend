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
from core.permissions import IsEagle, IsEagleOrAdmin, IsNestMember, IsNestOwnerFromURL

from .serializers import (
    NestListSerializer,
    NestDetailSerializer,
    NestCreateSerializer,
    MembershipSerializer,
    MentorshipRequestSerializer,
    MentorshipRequestCreateSerializer,
    NestPostSerializer,
    NestPostCreateSerializer,
    NestResourceSerializer,
    NestResourceCreateSerializer,
    NestEventSerializer,
    NestEventCreateSerializer,
)
from .services import NestService, MembershipService, CommunityService


class NestViewSet(ViewSet):
    """
    Nest CRUD operations.

    GET  /nests/           → list (public + user's)
    POST /nests/           → create (Eagle only)
    GET  /nests/{id}/      → detail
    PATCH /nests/{id}/     → update (owner only)
    DELETE /nests/{id}/    → soft-delete (owner only)
    GET  /nests/my/        → eaglet's nests
    """

    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def list(self, request):
        """List public nests; Eagles see their own too."""
        if request.user.role == "eagle":
            nests = NestService.get_eagle_nests(request.user)
        else:
            nests = NestService.get_public_nests()

        # Fix N+1: Annotate member_count (excluding the eagle/owner) and calculate is_full
        nests = nests.annotate(
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
            nest = (
                Nest.objects
                .select_related("eagle")
                .annotate(
                    annotated_member_count=Count(
                        'memberships',
                        filter=Q(memberships__status='active') & ~Q(memberships__user=F('eagle'))
                    )
                )
                .annotate(
                    annotated_is_full=ExpressionWrapper(
                        Q(annotated_member_count__gte=F('max_members')),
                        output_field=BooleanField()
                    )
                )
                .get(pk=pk)
            )
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
                "full_name": m.user.get_full_name(),
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

    @action(detail=False, methods=["get"], url_path="my")
    def my_nests(self, request):
        """List nests the current eaglet belongs to."""
        nests = NestService.get_eaglet_nests(request.user)
        serializer = NestListSerializer(nests, many=True)
        return Response({"success": True, "data": serializer.data})

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
        """Eaglet requests to join a Nest."""
        serializer = MentorshipRequestCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        req = MembershipService.request_to_join(
            request.user, nest_pk, serializer.validated_data.get("message", "")
        )
        return Response(
            {"success": True, "data": MentorshipRequestSerializer(req).data},
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, nest_pk=None, pk=None):
        """Approve or reject a mentorship request."""
        action_type = request.data.get("action")

        if action_type == "approve":
            membership = MembershipService.approve_request(request.user, pk)
            return Response(
                {"success": True, "data": MembershipSerializer(membership).data}
            )
        elif action_type == "reject":
            req = MembershipService.reject_request(request.user, pk)
            return Response(
                {"success": True, "data": MentorshipRequestSerializer(req).data}
            )

        return Response(
            {"success": False, "error": {"message": "action must be 'approve' or 'reject'."}},
            status=status.HTTP_400_BAD_REQUEST,
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

    permission_classes = [IsAuthenticated, IsNestMember]

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

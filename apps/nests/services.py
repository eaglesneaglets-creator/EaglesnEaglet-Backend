"""
Nest Services

Business logic for Nest management, memberships, and mentorship requests.
Views should delegate all domain logic here — thin views, fat services.
"""

import logging
from typing import Optional

from django.db import transaction
from django.db.models import F, Prefetch
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.exceptions import (
    NotFound,
    PermissionDenied,
    ValidationError,
)

from .models import (
    Nest,
    NestMembership,
    MentorshipRequest,
    NestPost,
    NestPostComment,
    NestPostLike,
    NestResource,
    NestEvent,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Nest CRUD
# ---------------------------------------------------------------------------

class NestService:
    """Handles Nest creation, updates, and querying."""

    @staticmethod
    @transaction.atomic
    def create_nest(eagle, data: dict) -> Nest:
        """Create a Nest and auto-add the Eagle as an owner membership."""
        if eagle.role != "eagle":
            raise PermissionDenied("Only Eagles can create Nests.")

        nest = Nest.objects.create(eagle=eagle, **data)

        # Eagle gets an implicit membership as eagle_scout
        NestMembership.objects.create(
            nest=nest,
            user=eagle,
            role=NestMembership.MemberRole.EAGLE_SCOUT,
            status=NestMembership.Status.ACTIVE,
        )

        logger.info("Nest created: %s by %s", nest.name, eagle.email)
        return nest

    @staticmethod
    def update_nest(nest: Nest, eagle, data: dict) -> Nest:
        """Update a Nest; only the owner can modify."""
        if nest.eagle_id != eagle.id:
            raise PermissionDenied("Only the Nest owner can update it.")

        for field, value in data.items():
            setattr(nest, field, value)
        nest.save()
        return nest

    @staticmethod
    def get_eagle_nests(eagle):
        """Return all Nests owned by an Eagle."""
        return Nest.objects.filter(eagle=eagle).select_related("eagle")

    @staticmethod
    def get_public_nests():
        """Return active public Nests for browsing."""
        return (
            Nest.objects.filter(is_active=True, privacy=Nest.Privacy.PUBLIC)
            .select_related("eagle")
        )

    @staticmethod
    def get_eaglet_nests(eaglet):
        """Return Nests an Eaglet is a member of."""
        return Nest.objects.filter(
            memberships__user=eaglet,
            memberships__status="active",
        ).select_related("eagle")


# ---------------------------------------------------------------------------
# Membership
# ---------------------------------------------------------------------------

class MembershipService:
    """Handles membership operations: join, approve, remove."""

    @staticmethod
    @transaction.atomic
    def request_to_join(eaglet, nest_id: str, message: str = "") -> MentorshipRequest:
        """Eaglet requests to join a Nest."""
        try:
            nest = Nest.objects.get(pk=nest_id, is_active=True)
        except Nest.DoesNotExist:
            raise NotFound("Nest not found.")

        if eaglet.role != "eaglet":
            raise PermissionDenied("Only Eaglets can request to join a Nest.")

        if nest.is_full:
            raise ValidationError({"nest": "This Nest is full."})

        # Check for existing active membership
        if NestMembership.objects.filter(
            nest=nest, user=eaglet, status="active"
        ).exists():
            raise ValidationError({"nest": "You are already a member of this Nest."})

        # Check for existing pending request
        if MentorshipRequest.objects.filter(
            nest=nest, eaglet=eaglet, status="pending"
        ).exists():
            raise ValidationError({"nest": "You already have a pending request."})

        request = MentorshipRequest.objects.create(
            nest=nest,
            eaglet=eaglet,
            message=message,
        )
        logger.info("Mentorship request: %s → %s", eaglet.email, nest.name)
        return request

    @staticmethod
    @transaction.atomic
    def approve_request(eagle, request_id: str) -> NestMembership:
        """Eagle approves a mentorship request, creating a membership."""
        try:
            req = MentorshipRequest.objects.select_related("nest", "eaglet").get(
                pk=request_id, status="pending"
            )
        except MentorshipRequest.DoesNotExist:
            raise NotFound("Request not found or already processed.")

        if req.nest.eagle_id != eagle.id:
            raise PermissionDenied("Only the Nest owner can approve requests.")

        if req.nest.is_full:
            raise ValidationError({"nest": "This Nest is full."})

        req.status = MentorshipRequest.Status.APPROVED
        req.reviewed_by = eagle
        req.reviewed_at = timezone.now()
        req.save(update_fields=["status", "reviewed_by", "reviewed_at"])

        membership, _ = NestMembership.objects.get_or_create(
            nest=req.nest,
            user=req.eaglet,
            defaults={
                "role": NestMembership.MemberRole.MEMBER,
                "status": NestMembership.Status.ACTIVE,
            },
        )
        # If previously removed, reactivate
        if membership.status != "active":
            membership.status = NestMembership.Status.ACTIVE
            membership.save(update_fields=["status"])

        logger.info("Request approved: %s → %s", req.eaglet.email, req.nest.name)
        return membership

    @staticmethod
    @transaction.atomic
    def reject_request(eagle, request_id: str) -> MentorshipRequest:
        """Eagle rejects a mentorship request."""
        try:
            req = MentorshipRequest.objects.select_related("nest").get(
                pk=request_id, status="pending"
            )
        except MentorshipRequest.DoesNotExist:
            raise NotFound("Request not found or already processed.")

        if req.nest.eagle_id != eagle.id:
            raise PermissionDenied("Only the Nest owner can reject requests.")

        req.status = MentorshipRequest.Status.REJECTED
        req.reviewed_by = eagle
        req.reviewed_at = timezone.now()
        req.save(update_fields=["status", "reviewed_by", "reviewed_at"])

        logger.info("Request rejected: %s → %s", req.eaglet.email, req.nest.name)
        return req

    @staticmethod
    def remove_member(eagle, membership_id: str) -> NestMembership:
        """Eagle removes an inactive Eaglet from the Nest."""
        try:
            membership = NestMembership.objects.select_related("nest").get(
                pk=membership_id
            )
        except NestMembership.DoesNotExist:
            raise NotFound("Membership not found.")

        if membership.nest.eagle_id != eagle.id:
            raise PermissionDenied("Only the Nest owner can remove members.")

        # Don't allow removing the Eagle themselves
        if membership.user_id == eagle.id:
            raise ValidationError({"membership": "Cannot remove the Nest owner."})

        membership.status = NestMembership.Status.REMOVED
        membership.save(update_fields=["status"])

        logger.info("Member removed: %s from %s", membership.user_id, membership.nest.name)
        return membership

    @staticmethod
    def get_nest_members(nest_id: str, status: Optional[str] = "active"):
        """Return members of a Nest, optionally filtered by status. Excludes the nest owner."""
        qs = (
            NestMembership.objects
            .filter(nest_id=nest_id)
            .exclude(user=F('nest__eagle'))
            .select_related("user", "nest")
        )
        if status:
            qs = qs.filter(status=status)
        return qs

    @staticmethod
    def get_pending_requests(nest_id: str):
        """Return pending mentorship requests for a Nest."""
        return (
            MentorshipRequest.objects.filter(nest_id=nest_id, status="pending")
            .select_related("eaglet")
        )

    @staticmethod
    def get_eaglet_requests(eaglet):
        """Return all mentorship requests made by an Eaglet."""
        return (
            MentorshipRequest.objects.filter(eaglet=eaglet)
            .select_related("nest", "nest__eagle")
            .order_by("-created_at")
        )


# ---------------------------------------------------------------------------
# Community — posts, resources, events
# ---------------------------------------------------------------------------

class CommunityService:
    """Handles Nest community features: posts, resources, events."""

    @staticmethod
    def create_post(author, nest_id: str, data: dict) -> NestPost:
        """Create a post in a Nest feed."""
        # Verify membership
        if not NestMembership.objects.filter(
            nest_id=nest_id, user=author, status="active"
        ).exists():
            raise PermissionDenied("You must be an active member to post.")

        post = NestPost.objects.create(nest_id=nest_id, author=author, **data)

        # Award gamification points to eaglets only
        if author.role == "eaglet":
            from apps.points.services import PointService
            PointService.award_points(
                author,
                "post_created",
                source_id=str(post.id),
                nest=post.nest,
            )

        return post

    @staticmethod
    def get_nest_posts(nest_id: str):
        """Return posts for a Nest feed, newest first."""
        return (
            NestPost.objects.filter(nest_id=nest_id)
            .select_related("author")
            .prefetch_related("comments__author")
        )

    @staticmethod
    def add_comment(author, post_id: str, content: str) -> NestPostComment:
        """Add a comment to a Nest post."""
        try:
            post = NestPost.objects.get(pk=post_id)
        except NestPost.DoesNotExist:
            raise NotFound("Post not found.")

        if not NestMembership.objects.filter(
            nest_id=post.nest_id, user=author, status="active"
        ).exists():
            raise PermissionDenied("You must be an active member to comment.")

        comment = NestPostComment.objects.create(
            post=post, author=author, content=content
        )
        # Update denormalized count
        NestPost.objects.filter(pk=post_id).update(
            comments_count=F("comments_count") + 1
        )
        return comment

    @staticmethod
    def toggle_like(post_id: str, user) -> dict:
        """Toggle a like on a post. Returns liked status and the authoritative count."""
        post = get_object_or_404(NestPost, id=post_id)
        like, created = NestPostLike.objects.get_or_create(post=post, user=user)
        if not created:
            like.delete()
            NestPost.objects.filter(id=post_id).update(likes_count=F("likes_count") - 1)
            liked = False
        else:
            NestPost.objects.filter(id=post_id).update(likes_count=F("likes_count") + 1)
            liked = True
        post.refresh_from_db(fields=["likes_count"])
        return {"liked": liked, "likes_count": post.likes_count}

    @staticmethod
    def get_comments(post_id: str):
        """Return top-level comments (parent=None) with replies prefetched."""
        return (
            NestPostComment.objects.filter(post_id=post_id, parent=None)
            .select_related("author")
            .prefetch_related(
                Prefetch(
                    "replies",
                    queryset=NestPostComment.objects.select_related("author").order_by(
                        "created_at"
                    ),
                )
            )
            .order_by("created_at")
        )

    @staticmethod
    def add_reply(comment_id: str, author, content: str) -> NestPostComment:
        """Add a reply to a top-level comment. Raises ValidationError if target is a reply."""
        parent = get_object_or_404(NestPostComment, id=comment_id)
        if parent.parent_id is not None:
            raise ValidationError(
                "Cannot reply to a reply. Only one level of threading is allowed."
            )
        return NestPostComment.objects.create(
            post=parent.post,
            author=author,
            content=content,
            parent=parent,
        )

    @staticmethod
    def upload_resource(uploader, nest_id: str, data: dict) -> NestResource:
        """Upload a resource to the Nest shared library."""
        if not NestMembership.objects.filter(
            nest_id=nest_id, user=uploader, status="active"
        ).exists():
            raise PermissionDenied("You must be an active member to upload resources.")

        return NestResource.objects.create(
            nest_id=nest_id, uploaded_by=uploader, **data
        )

    @staticmethod
    def get_nest_resources(nest_id: str):
        """Return shared resources for a Nest."""
        return NestResource.objects.filter(nest_id=nest_id).select_related(
            "uploaded_by"
        )

    @staticmethod
    def create_event(eagle, nest_id: str, data: dict) -> NestEvent:
        """Create a scheduled event in a Nest (Eagle only)."""
        try:
            nest = Nest.objects.get(pk=nest_id)
        except Nest.DoesNotExist:
            raise NotFound("Nest not found.")

        if nest.eagle_id != eagle.id:
            raise PermissionDenied("Only the Nest owner can create events.")

        return NestEvent.objects.create(
            nest=nest, created_by=eagle, **data
        )

    @staticmethod
    def get_nest_events(nest_id: str):
        """Return upcoming events for a Nest."""
        return NestEvent.objects.filter(
            nest_id=nest_id,
            event_date__gte=timezone.now(),
        ).select_related("created_by")

    @staticmethod
    def mark_attendance(user, event_id: str):
        """
        Mark a user's attendance at a NestEvent.

        Only eaglets earn gamification points.
        Idempotent: the DB unique constraint prevents duplicate attendance.
        """
        from .models import EventAttendance

        try:
            event = NestEvent.objects.select_related("nest").get(pk=event_id)
        except NestEvent.DoesNotExist:
            raise NotFound("Event not found.")

        if not NestMembership.objects.filter(
            nest=event.nest, user=user, status="active"
        ).exists():
            raise PermissionDenied("You must be an active member to mark attendance.")

        attendance, created = EventAttendance.objects.get_or_create(
            event=event, user=user,
        )

        if not created:
            raise ValidationError("You have already marked attendance for this event.")

        # Award points to eaglets only
        if user.role == "eaglet":
            from apps.points.services import PointService
            PointService.award_points(
                user,
                "event_attended",
                source_id=str(event.id),
                nest=event.nest,
            )

        return attendance

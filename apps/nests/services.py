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
from .models_program import (
    Program,
    ProgramEnrollment,
    ProgramExitRequest,
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

        # Lock the Nest row so concurrent approvals cannot both pass the is_full
        # check before either transaction commits (H7 — member_count race).
        nest = Nest.objects.select_for_update().get(pk=req.nest_id)
        if nest.is_full:
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

def _can_participate_in_nest(user, nest_id: str) -> bool:
    """True iff ``user`` may post / comment / upload in the given Nest.

    Mirrors the IsNestMember permission contract so the service layer doesn't
    fork from the view-layer check:
      - Platform admins bypass (is_staff or is_superuser).
      - The owning Eagle (Nest.eagle FK) is always allowed — they don't carry a
        NestMembership row for their own Nest, which used to lock them out.
      - Otherwise the user must hold an ACTIVE NestMembership.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.is_staff or user.is_superuser:
        return True
    if Nest.objects.filter(pk=nest_id, eagle=user).exists():
        return True
    return NestMembership.objects.filter(
        nest_id=nest_id, user=user, status="active",
    ).exists()


class CommunityService:
    """Handles Nest community features: posts, resources, events."""

    @staticmethod
    def create_post(author, nest_id: str, data: dict) -> NestPost:
        """Create a post in a Nest feed."""
        if not _can_participate_in_nest(author, nest_id):
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

        if not _can_participate_in_nest(author, post.nest_id):
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
        if not _can_participate_in_nest(uploader, nest_id):
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

        if not _can_participate_in_nest(user, event.nest_id):
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


# ---------------------------------------------------------------------------
# Program Enrollment lifecycle (plan 14-02)
# ---------------------------------------------------------------------------


class EnrollmentError(Exception):
    """Base for enrollment lifecycle errors. Carries error_code for FE handling."""
    error_code = "enrollment_error"

    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        if error_code:
            self.error_code = error_code


class AlreadyEnrolled(EnrollmentError):
    error_code = "already_enrolled"


class NoActiveProgram(EnrollmentError):
    error_code = "no_active_program"


class InvalidTransition(EnrollmentError):
    error_code = "invalid_transition"


def _snapshot_program_rules(program: Program) -> dict:
    """Capture objective + rule definitions at approval time so later edits to
    the program don't move the finish line for existing enrollees."""
    objectives = []
    for objective in program.objectives.prefetch_related("rules").all():
        objectives.append({
            "id": str(objective.id),
            "title": objective.title,
            "order": objective.order,
            "rules": [
                {
                    "id": str(r.id),
                    "rule_type": r.rule_type,
                    "target": r.target,
                    "config": r.config,
                }
                for r in objective.rules.all()
            ],
        })
    return {
        "program_id": str(program.id),
        "snapshotted_at": timezone.now().isoformat(),
        "objectives": objectives,
    }


class EnrollmentService:
    """Single source of truth for ProgramEnrollment lifecycle transitions."""

    # ------------------------- Apply -------------------------

    @staticmethod
    @transaction.atomic
    def apply(*, mentee, nest, message: str = "") -> ProgramEnrollment:
        if mentee.role != "eaglet":
            raise PermissionDenied("Only Eaglets can apply to programs.")

        program = Program.objects.filter(
            nest=nest, status=Program.Status.ACTIVE
        ).first()
        if program is None:
            raise NoActiveProgram(
                "This Nest has no active program to apply to."
            )

        # v1 invariants — service-layer pre-check (Postgres partial unique
        # is the floor; this gives clean error messages cross-DB).
        if ProgramEnrollment.objects.filter(
            mentee=mentee, status=ProgramEnrollment.Status.PENDING
        ).exists():
            raise AlreadyEnrolled(
                "You already have a pending program application."
            )
        if ProgramEnrollment.objects.filter(
            mentee=mentee, status=ProgramEnrollment.Status.ACTIVE
        ).exists():
            raise AlreadyEnrolled(
                "You already have an active program enrollment."
            )

        enrollment = ProgramEnrollment.objects.create(
            program=program,
            mentee=mentee,
            application_message=message,
        )
        logger.info(
            "Program application: %s → %s (program=%s)",
            mentee.email, nest.name, program.id,
        )
        return enrollment

    # ------------------------- Approve -------------------------

    @staticmethod
    @transaction.atomic
    def approve(*, enrollment_id: str, reviewer) -> ProgramEnrollment:
        enrollment = (
            ProgramEnrollment.objects
            .select_for_update()
            .select_related("program__nest")
            .get(pk=enrollment_id)
        )
        if enrollment.status != ProgramEnrollment.Status.PENDING:
            raise InvalidTransition(
                f"Cannot approve enrollment in status '{enrollment.status}'."
            )

        # Race guard — mentee may already have active enrollment elsewhere
        if ProgramEnrollment.objects.filter(
            mentee=enrollment.mentee,
            status=ProgramEnrollment.Status.ACTIVE,
        ).exists():
            raise AlreadyEnrolled(
                "Mentee already has an active enrollment."
            )

        enrollment.status = ProgramEnrollment.Status.ACTIVE
        enrollment.started_at = timezone.now()
        enrollment.reviewed_by = reviewer
        enrollment.rules_snapshot = _snapshot_program_rules(enrollment.program)
        enrollment.save(update_fields=[
            "status", "started_at", "reviewed_by", "rules_snapshot", "updated_at",
        ])
        logger.info(
            "Enrollment approved: %s (mentee=%s)",
            enrollment.id, enrollment.mentee_id,
        )
        return enrollment

    # ------------------------- Reject -------------------------

    @staticmethod
    @transaction.atomic
    def reject(*, enrollment_id: str, reviewer, reason: str = "") -> ProgramEnrollment:
        enrollment = ProgramEnrollment.objects.select_for_update().get(pk=enrollment_id)
        if enrollment.status != ProgramEnrollment.Status.PENDING:
            raise InvalidTransition(
                f"Cannot reject enrollment in status '{enrollment.status}'."
            )
        enrollment.status = ProgramEnrollment.Status.REJECTED
        enrollment.ended_at = timezone.now()
        enrollment.reviewed_by = reviewer
        enrollment.ended_by = reviewer
        enrollment.exit_reason = reason
        enrollment.save(update_fields=[
            "status", "ended_at", "reviewed_by", "ended_by", "exit_reason", "updated_at",
        ])
        return enrollment

    # ------------------------- Release -------------------------

    @staticmethod
    @transaction.atomic
    def release(*, enrollment_id: str, actor, reason: str = "") -> ProgramEnrollment:
        enrollment = ProgramEnrollment.objects.select_for_update().get(pk=enrollment_id)
        if enrollment.status != ProgramEnrollment.Status.ACTIVE:
            raise InvalidTransition(
                f"Cannot release enrollment in status '{enrollment.status}'."
            )
        enrollment.status = ProgramEnrollment.Status.RELEASED
        enrollment.ended_at = timezone.now()
        enrollment.ended_by = actor
        enrollment.exit_reason = reason
        enrollment.save(update_fields=[
            "status", "ended_at", "ended_by", "exit_reason", "updated_at",
        ])
        return enrollment

    # ------------------------- Complete -------------------------

    @staticmethod
    @transaction.atomic
    def complete(*, enrollment_id: str, actor, force: bool = False) -> ProgramEnrollment:
        """Mark active enrollment complete.

        Validates that all objective rules in the enrollment's locked
        rules_snapshot are met. `force=True` (staff only — caller enforces)
        bypasses the check for emergency completion and emits an audit log.
        """
        enrollment = ProgramEnrollment.objects.select_for_update().get(pk=enrollment_id)
        if enrollment.status != ProgramEnrollment.Status.ACTIVE:
            raise InvalidTransition(
                f"Cannot complete enrollment in status '{enrollment.status}'."
            )

        if not force:
            from apps.nests.evaluators import evaluate_enrollment

            progress = evaluate_enrollment(enrollment)
            if not progress["all_met"]:
                raise InvalidTransition(
                    "Cannot complete: not all objectives met.",
                    error_code="objectives_incomplete",
                )

        enrollment.status = ProgramEnrollment.Status.COMPLETED
        enrollment.ended_at = timezone.now()
        enrollment.ended_by = actor
        enrollment.save(update_fields=[
            "status", "ended_at", "ended_by", "updated_at",
        ])
        if force:
            logger.warning(
                "Enrollment force-completed: enrollment=%s actor=%s",
                enrollment.id, getattr(actor, "id", None),
            )
        return enrollment

    # ------------------------- Opt-out request -------------------------

    @staticmethod
    @transaction.atomic
    def request_opt_out(*, enrollment_id: str, mentee, reason: str) -> ProgramExitRequest:
        enrollment = ProgramEnrollment.objects.select_for_update().get(pk=enrollment_id)
        if enrollment.mentee_id != mentee.id:
            raise PermissionDenied("Only the enrolled mentee can request opt-out.")
        if enrollment.status != ProgramEnrollment.Status.ACTIVE:
            raise InvalidTransition(
                "Only active enrollments can request opt-out."
            )
        if not reason or not reason.strip():
            raise ValidationError({"reason": "A reason is required."})
        if ProgramExitRequest.objects.filter(
            enrollment=enrollment, status=ProgramExitRequest.Status.PENDING
        ).exists():
            raise ValidationError({
                "exit_request": "You already have a pending opt-out request."
            })
        exit_req = ProgramExitRequest.objects.create(
            enrollment=enrollment,
            requested_by=mentee,
            reason=reason,
        )
        return exit_req

    # ------------------------- Decide opt-out -------------------------

    @staticmethod
    @transaction.atomic
    def decide_opt_out(
        *, exit_request_id: str, decider, approve: bool, note: str = ""
    ) -> ProgramExitRequest:
        exit_req = (
            ProgramExitRequest.objects
            .select_for_update()
            .select_related("enrollment")
            .get(pk=exit_request_id)
        )
        if exit_req.status != ProgramExitRequest.Status.PENDING:
            raise InvalidTransition(
                "Exit request already decided."
            )
        exit_req.status = (
            ProgramExitRequest.Status.APPROVED if approve
            else ProgramExitRequest.Status.DENIED
        )
        exit_req.decided_by = decider
        exit_req.decided_at = timezone.now()
        exit_req.decision_note = note
        exit_req.save(update_fields=[
            "status", "decided_by", "decided_at", "decision_note", "updated_at",
        ])
        if approve:
            enrollment = exit_req.enrollment
            enrollment.status = ProgramEnrollment.Status.OPTED_OUT
            enrollment.ended_at = timezone.now()
            enrollment.ended_by = decider
            enrollment.exit_reason = exit_req.reason
            enrollment.save(update_fields=[
                "status", "ended_at", "ended_by", "exit_reason", "updated_at",
            ])
        return exit_req

    # ------------------------- access_status -------------------------

    @staticmethod
    def access_status_for(user) -> dict:
        """Build the FE access_status payload for a mentee."""
        from .levels import compute_level
        level = compute_level(user)
        active = (
            ProgramEnrollment.objects
            .filter(mentee=user, status=ProgramEnrollment.Status.ACTIVE)
            .select_related("program__nest")
            .first()
        )
        pending = (
            ProgramEnrollment.objects
            .filter(mentee=user, status=ProgramEnrollment.Status.PENDING)
            .select_related("program__nest")
            .first()
        )
        return {
            "has_active_program": bool(active),
            "active_program": (
                {
                    "enrollment_id": str(active.id),
                    "program_id": str(active.program_id),
                    "program_name": active.program.name,
                    # FE convenience aliases (MyProgramTab reads these directly).
                    "name": active.program.name,
                    "description": active.program.description,
                    "status": active.status,
                    "nest_id": str(active.program.nest_id),
                    "nest_name": active.program.nest.name,
                    "started_at": active.started_at,
                    # Snapshot taken at approval — single source of truth for
                    # required objective/rule counts regardless of later edits.
                    "objectives_count": len((active.rules_snapshot or {}).get("objectives", [])),
                    "objectives_completed": 0,  # TODO wire real evaluator in next plan
                } if active else None
            ),
            "pending_program_request": (
                {
                    "enrollment_id": str(pending.id),
                    "program_name": pending.program.name,
                    "nest_name": pending.program.nest.name,
                    "requested_at": pending.requested_at,
                } if pending else None
            ),
            "locked_features": [] if active else ["assignments", "messages", "resources", "leaderboard"],
            "mentee_level": level,
            "mentor_eligibility": level["mentor_eligible"],
        }


# ---------------------------------------------------------------------------
# Program discovery helpers (plan 14.5-01)
# ---------------------------------------------------------------------------

_RULE_SUMMARY_TEMPLATES = {
    "modules_completed": "Complete {n} module{s}",
    "assignments_passed": "Pass {n} assignment{s}",
    "points_earned": "Earn {n} point{s}",
    "posts_count": "Post {n} time{s}",
    "streak_days": "Maintain a {n}-day streak",
}


def build_rule_summary_string(rule) -> str:
    """Render one ProgramObjectiveRule as a human-readable phrase."""
    template = _RULE_SUMMARY_TEMPLATES.get(rule.rule_type)
    if template is None:
        return f"{rule.rule_type}: {rule.target}"
    return template.format(n=rule.target, s="" if rule.target == 1 else "s")


def build_objective_rule_summary(objective) -> str:
    """Join all rules of an objective into one ' · ' separated summary string.

    Used by mentee discovery surface so prospective mentees see what completing
    the objective requires before they apply to the program.
    """
    rules = list(objective.rules.all())
    if not rules:
        return "No measurable rules"
    return " · ".join(build_rule_summary_string(r) for r in rules)

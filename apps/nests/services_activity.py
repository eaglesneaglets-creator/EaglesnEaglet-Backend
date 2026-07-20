"""
Admin nest oversight service + activity helpers (Phase 27-01).

Kept apart from services.py (mentor/eaglet domain logic) so the admin surface
is easy to find and doesn't bloat the core service.
"""

import logging

from django.db.models import Count, F, Q
from rest_framework.exceptions import NotFound, ValidationError

from .models import Nest, NestMembership
from .models_activity import NestActivity

logger = logging.getLogger(__name__)


def record_admin_activity(nest, actor, action_type, target="", **metadata):
    """Record an admin-initiated NestActivity (actor is the acting admin)."""
    return NestActivity.objects.create(
        nest=nest,
        actor=actor,
        action_type=action_type,
        target=target or "",
        metadata=metadata or {},
    )


class NestAdminService:
    """Platform-wide nest oversight for superadmins."""

    @staticmethod
    def list_all_nests(*, status=None, category=None, search=None, include_archived=False):
        """Return a queryset of ALL nests, annotated + filtered.

        `member_count` is annotated at the queryset level (no N+1). The UI
        "status" (active / forming / completed / archived) is derived in the
        serializer from is_active + member_count, so we DON'T filter on a
        stored status column — we filter in Python-friendly terms below.
        """
        qs = (
            Nest.objects.all()  # SoftDeleteMixin default manager excludes soft-deleted
            if not include_archived
            else Nest.all_objects.all()
        )
        # Annotate active member count at the queryset level (no N+1 via the
        # model @property). Excludes the eagle's own owner-membership to match
        # the "8/10 eaglets" count the mentor sees on their own nest surface
        # (same predicate as views._annotate_nest_counts).
        qs = qs.select_related("eagle").annotate(
            annotated_member_count=Count(
                "memberships",
                filter=Q(memberships__status="active") & ~Q(memberships__user=F("eagle")),
                distinct=True,
            )
        )

        if category:
            qs = qs.filter(category=category)
        if search:
            qs = qs.filter(
                Q(name__icontains=search)
                | Q(description__icontains=search)
                | Q(eagle__first_name__icontains=search)
                | Q(eagle__last_name__icontains=search)
            )

        # Derived-status filter: map the UI status to queryset predicates while
        # preserving the member_count annotation.
        if status == "forming":
            qs = qs.filter(is_active=True, annotated_member_count=0)
        elif status == "active":
            qs = qs.filter(is_active=True, annotated_member_count__gt=0)
        elif status == "archived":
            # Archived nests are soft-deleted → only visible via all_objects.
            # Re-derive from all_objects but keep the same annotation.
            qs = (
                Nest.all_objects.filter(is_active=False)
                .select_related("eagle")
                .annotate(
                    annotated_member_count=Count(
                        "memberships",
                        filter=Q(memberships__status="active")
                        & ~Q(memberships__user=F("eagle")),
                        distinct=True,
                    )
                )
            )
            if category:
                qs = qs.filter(category=category)
            if search:
                qs = qs.filter(
                    Q(name__icontains=search)
                    | Q(description__icontains=search)
                    | Q(eagle__first_name__icontains=search)
                    | Q(eagle__last_name__icontains=search)
                )
        # status in (None, 'all', 'completed') → no extra status filter.

        return qs.order_by("-created_at")

    @staticmethod
    def create_on_behalf(admin, data: dict) -> Nest:
        """Admin creates a nest and assigns a chosen mentor as owner."""
        eagle = data.pop("eagle")

        if eagle.role != "eagle":
            raise ValidationError({"eagle_id": "Assigned owner must be a mentor (Eagle)."})

        kyc = getattr(eagle, "mentor_kyc", None)
        if kyc is None or kyc.status != "approved":
            raise ValidationError(
                {"eagle_id": "Mentor must have an approved KYC before owning a nest."}
            )

        nest = Nest.objects.create(eagle=eagle, **data)

        # Eagle gets the implicit owner membership (same as NestService.create_nest).
        NestMembership.objects.create(
            nest=nest,
            user=eagle,
            role=NestMembership.MemberRole.EAGLE_SCOUT,
            status=NestMembership.Status.ACTIVE,
        )

        record_admin_activity(
            nest, admin, NestActivity.ActionType.NEST_CREATED,
            target=nest.name, on_behalf_of=str(eagle.id),
        )
        logger.info("Admin %s created nest '%s' for eagle %s", admin.email, nest.name, eagle.email)
        return nest

    @staticmethod
    def archive_nest(admin, nest_id: str) -> Nest:
        """Soft-delete + deactivate a nest, recording the admin action."""
        try:
            nest = Nest.objects.get(pk=nest_id)
        except Nest.DoesNotExist:
            raise NotFound("Nest not found.")

        nest.is_active = False
        nest.save(update_fields=["is_active"])
        record_admin_activity(
            nest, admin, NestActivity.ActionType.NEST_ARCHIVED, target=nest.name,
        )
        nest.soft_delete()  # SoftDeleteMixin — hides from default manager
        logger.info("Admin %s archived nest '%s'", admin.email, nest.name)
        return nest

    @staticmethod
    def remove_member(admin, nest_id: str, membership_id: str) -> NestMembership:
        """Admin removes a member from any nest (bypasses owner-only guard)."""
        try:
            membership = NestMembership.objects.select_related("nest", "user").get(
                pk=membership_id, nest_id=nest_id
            )
        except NestMembership.DoesNotExist:
            raise NotFound("Membership not found.")

        if membership.user_id == membership.nest.eagle_id:
            raise ValidationError({"membership": "Cannot remove the Nest owner."})

        name = getattr(membership.user, "full_name", None) or str(membership.user)
        membership.status = NestMembership.Status.REMOVED
        # Suppress the organic-leave signal; we log the admin-attributed event instead.
        membership._skip_activity_signal = True
        membership.save(update_fields=["status"])

        record_admin_activity(
            membership.nest, admin,
            NestActivity.ActionType.MEMBER_REMOVED, target=name,
        )
        logger.info("Admin %s removed member %s from nest %s", admin.email, name, membership.nest_id)
        return membership

    @staticmethod
    def get_nest_activity(nest_id: str):
        """Return a nest's activity log, newest-first (for pagination)."""
        if not Nest.all_objects.filter(pk=nest_id).exists():
            raise NotFound("Nest not found.")
        return NestActivity.objects.filter(nest_id=nest_id).select_related("actor")

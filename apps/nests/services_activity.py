"""
Admin nest oversight service + activity helpers (Phase 27-01).

Kept apart from services.py (mentor/eaglet domain logic) so the admin surface
is easy to find and doesn't bloat the core service.
"""

import logging
import re

from django.db.models import Count, F, Q
from rest_framework.exceptions import NotFound, ValidationError

from .models import Nest, NestMembership
from .models_activity import NestActivity

logger = logging.getLogger(__name__)

# Bounded URL matcher for surfacing links shared in post text. Deliberately
# simple + length-capped (no backtracking blowup); we only surface the raw URL,
# never fetch it — OpenGraph/thumbnail unfurling is a separate future phase.
_URL_RE = re.compile(r"https?://[^\s<>\"]{1,300}")


def _display_name(user):
    return getattr(user, "full_name", None) or (str(user) if user else "Unknown")


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

    @staticmethod
    def get_shared_content(nest, limit=50):
        """Aggregate everything shared in a nest into one unified list.

        Three sources, newest-first, because "shared content" as a member sees
        it is not just the formal resource library:
          1. NestResource  — files/links uploaded to the resource library.
          2. NestPost.attachment_url — files/images attached to feed posts.
          3. URLs found in NestPost.content — links shared inline in posts.

        Returns plain dicts with a common shape so the serializer stays trivial:
        {kind, title, url, content_type, shared_by, created_at}. `kind` is one
        of 'resource' | 'attachment' | 'link'.
        """
        items = []

        for r in nest.resources.select_related("uploaded_by"):
            items.append({
                "kind": "resource",
                "title": r.title,
                "url": r.file_url,
                "content_type": r.file_type,
                "shared_by": _display_name(r.uploaded_by),
                "created_at": r.created_at,
            })

        for p in nest.posts.select_related("author"):
            if p.attachment_url:
                items.append({
                    "kind": "attachment",
                    "title": (p.content or "").strip()[:80] or "Attachment",
                    "url": p.attachment_url,
                    "content_type": p.attachment_type or "file",
                    "shared_by": _display_name(p.author),
                    "created_at": p.created_at,
                })
            # Inline links in the post body (excluding the attachment URL itself).
            for match in _URL_RE.findall(p.content or ""):
                if match == p.attachment_url:
                    continue
                items.append({
                    "kind": "link",
                    "title": match,
                    "url": match,
                    "content_type": "link",
                    "shared_by": _display_name(p.author),
                    "created_at": p.created_at,
                })

        items.sort(key=lambda i: i["created_at"], reverse=True)
        return items[:limit]

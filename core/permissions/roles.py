"""
Role-Based Access Control Permissions

DRF permission classes for Eagles & Eaglets platform.
Each class checks the authenticated user's role before allowing access.
"""

from rest_framework.permissions import BasePermission


class IsEagle(BasePermission):
    """Allow access only to Eagle (Mentor) users."""

    message = "Only Eagles (Mentors) can perform this action."

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and hasattr(request.user, "role")
            and request.user.role == "eagle"
        )


class IsEaglet(BasePermission):
    """Allow access only to Eaglet (Mentee) users."""

    message = "Only Eaglets (Mentees) can perform this action."

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and hasattr(request.user, "role")
            and request.user.role == "eaglet"
        )


class IsAdmin(BasePermission):
    """Allow access to any platform admin (scoped admin OR superadmin).

    Uses the canonical ``User.is_admin`` predicate (role==admin OR is_superuser
    OR is_platform_staff) so stacked admins — Eagles/Eaglets granted admin via
    the AdminRoleRequest flow, who have ``is_platform_staff`` but NOT Django's
    ``is_staff`` — are correctly recognised.
    """

    message = "Only Admins can perform this action."

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and u.is_admin)


class IsEagleOrAdmin(BasePermission):
    """Allow access to Eagle or Admin users."""

    message = "Only Eagles or Admins can perform this action."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        if request.user.is_admin:
            return True

        return hasattr(request.user, "role") and request.user.role == "eagle"


class IsNestOwner(BasePermission):
    """
    Allow access only to the Eagle who owns the Nest.

    Works as an object-level permission. The object should be the Nest
    itself or have a ``nest`` foreign key attribute.
    """

    message = "Only the Nest owner can perform this action."

    def has_object_permission(self, request, view, obj):
        nest = getattr(obj, "nest", obj)
        return nest.eagle_id == request.user.id


class IsNestMember(BasePermission):
    """
    Allow access to users who are members of the Nest.

    Resolves the nest from ``nest_pk`` or ``pk`` URL kwargs.
    Admins bypass this check.

    Plan 14.5-01: SAFE_METHODS (GET/HEAD/OPTIONS) allowed for both ACTIVE and
    INACTIVE memberships so terminal-enrollment mentees retain read-only access
    to past Nest content. Unsafe methods still require ACTIVE membership.
    """

    message = "You must be an active member of this Nest."

    def has_permission(self, request, view):
        from rest_framework.permissions import SAFE_METHODS

        if not request.user.is_authenticated:
            return False

        if request.user.is_admin:
            return True

        nest_id = view.kwargs.get("nest_pk") or view.kwargs.get("pk")
        if not nest_id:
            return False

        # Import here to avoid circular dependency with nests app
        from apps.nests.models import NestMembership, Nest

        membership_statuses = ("active", "inactive") if request.method in SAFE_METHODS else ("active",)
        is_member = NestMembership.objects.filter(
            nest_id=nest_id,
            user=request.user,
            status__in=membership_statuses,
        ).exists()

        if is_member:
            return True

        # Allow nest owner
        return Nest.objects.filter(
            pk=nest_id,
            eagle=request.user,
        ).exists()


class IsNestOwnerFromURL(BasePermission):
    """
    Allow access only to the Eagle who owns the Nest.

    Resolves the nest from ``nest_pk`` or ``pk`` URL kwargs.
    Admins bypass this check.
    """

    message = "Only the Nest owner can perform this action."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        if request.user.is_admin:
            return True

        nest_id = view.kwargs.get("nest_pk") or view.kwargs.get("pk")
        if not nest_id:
            return False

        from apps.nests.models import Nest

        return Nest.objects.filter(
            pk=nest_id,
            eagle=request.user,
        ).exists()


class IsPlatformAdmin(BasePermission):
    """Any platform admin — scoped admin OR superadmin (``User.is_admin``).

    Canonical predicate for admin-capability gates. Covers stacked Eagles /
    Eaglets granted via the AdminRoleRequest flow (``is_platform_staff``) as
    well as legacy ``role='admin'`` and Django superusers. Prefer this over
    hand-rolled ``is_staff``/``is_superuser`` checks.
    """

    message = "Admin access required."

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and u.is_admin)


class IsSuperAdmin(BasePermission):
    """Bootstrap superadmin only (``is_superuser``) — sensitive surfaces.

    Used for donations, store orders, platform nest management, admin settings,
    and admin-lifecycle actions that scoped (dual-role) admins must not reach.
    """

    message = "Superadmin access required."

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and u.is_superuser)

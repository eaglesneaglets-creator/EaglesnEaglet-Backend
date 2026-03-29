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
    """Allow access only to Admin users."""

    message = "Only Admins can perform this action."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.user.is_staff or request.user.is_superuser:
            return True
        return hasattr(request.user, "role") and request.user.role == "admin"


class IsEagleOrAdmin(BasePermission):
    """Allow access to Eagle or Admin users."""

    message = "Only Eagles or Admins can perform this action."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        if request.user.is_staff or request.user.is_superuser:
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
    Allow access to users who are active members of the Nest.

    Resolves the nest from ``nest_pk`` or ``pk`` URL kwargs.
    Admins bypass this check.
    """

    message = "You must be an active member of this Nest."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        if request.user.is_staff or request.user.is_superuser:
            return True

        nest_id = view.kwargs.get("nest_pk") or view.kwargs.get("pk")
        if not nest_id:
            return False

        # Import here to avoid circular dependency with nests app
        from apps.nests.models import NestMembership, Nest

        is_member = NestMembership.objects.filter(
            nest_id=nest_id,
            user=request.user,
            status="active",
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

        if request.user.is_staff or request.user.is_superuser:
            return True

        nest_id = view.kwargs.get("nest_pk") or view.kwargs.get("pk")
        if not nest_id:
            return False

        from apps.nests.models import Nest

        return Nest.objects.filter(
            pk=nest_id,
            eagle=request.user,
        ).exists()

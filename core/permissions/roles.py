"""
Role-based Permissions
Custom permissions for Eagle, Eaglet, and Admin roles
"""

from rest_framework.permissions import BasePermission


class IsEagle(BasePermission):
    """
    Permission check for Eagle (Mentor) users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and hasattr(request.user, "role")
            and request.user.role == "eagle"
        )


class IsEaglet(BasePermission):
    """
    Permission check for Eaglet (Mentee) users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and hasattr(request.user, "role")
            and request.user.role == "eaglet"
        )


class IsAdmin(BasePermission):
    """
    Permission check for Admin users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and (request.user.is_staff or request.user.is_superuser)
        )


class IsEagleOrAdmin(BasePermission):
    """
    Permission check for Eagle or Admin users.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        if request.user.is_staff or request.user.is_superuser:
            return True

        return hasattr(request.user, "role") and request.user.role == "eagle"

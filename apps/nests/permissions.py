"""
Nest app permissions.

Holds permission classes specific to the nests app. Cross-app role checks
live in `core.permissions.roles`; this module is for nest-internal authorization.
"""

from rest_framework import status
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.permissions import BasePermission

from .models import Nest


class NoActiveProgramDenied(PermissionDenied):
    """403 with FE-friendly error_code so the lock modal can be triggered."""
    default_code = "no_active_program"
    default_detail = "You need an active program enrollment to access this feature."


class ProgramRulesLockedException(APIException):
    """423 Locked. Plan 14.5-01: rules frozen once mentees enroll."""
    status_code = status.HTTP_423_LOCKED
    default_code = "ProgramRulesLocked"
    default_detail = (
        "Cannot modify program rules while mentees are enrolled. "
        "Archive this program and create a new version to change requirements."
    )
from .models_program import (
    Program,
    ProgramEnrollment,
    ProgramExitRequest,
    ProgramObjective,
    ProgramObjectiveRule,
)


def _resolve_nest(obj) -> Nest | None:
    """Walk Program / Objective / Rule / Enrollment chains back to the owning Nest."""
    if isinstance(obj, Program):
        return obj.nest
    if isinstance(obj, ProgramObjective):
        return obj.program.nest
    if isinstance(obj, ProgramObjectiveRule):
        return obj.objective.program.nest
    if isinstance(obj, ProgramEnrollment):
        return obj.program.nest
    if isinstance(obj, ProgramExitRequest):
        return obj.enrollment.program.nest
    return None


class IsProgramAdmin(BasePermission):
    """
    Allow nest owner (the Eagle who owns the Nest) OR platform staff.

    Object-level check walks Program / ProgramObjective / ProgramObjectiveRule
    instances back to their owning Nest and compares against `nest.eagle_id`.
    """

    message = "Only the nest owner or platform staff can manage this program."

    def has_permission(self, request, view) -> bool:
        user = request.user
        if not user or not user.is_authenticated:
            return False
        return user.is_staff or getattr(user, "role", None) == "eagle"

    def has_object_permission(self, request, view, obj) -> bool:
        if request.user.is_staff:
            return True
        nest = _resolve_nest(obj)
        return nest is not None and nest.eagle_id == request.user.id


class HasActiveProgram(BasePermission):
    """
    Allow only mentees with an active ProgramEnrollment. Used by gated feature
    endpoints (assignments, messages, resources — wired in 14-03). Eagles +
    admins bypass; their access is governed by other permission classes.
    """

    message = "You need an active program enrollment to access this feature."

    def has_permission(self, request, view) -> bool:
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_staff or getattr(user, "role", None) != "eaglet":
            return True
        if ProgramEnrollment.objects.filter(
            mentee=user, status=ProgramEnrollment.Status.ACTIVE,
        ).exists():
            return True
        raise NoActiveProgramDenied()


class IsPlatformAdmin(BasePermission):
    """Admin-only access (is_staff OR role='admin'). Used for level-config CRUD."""

    message = "Admin access required."

    def has_permission(self, request, view) -> bool:
        user = request.user
        if not user or not user.is_authenticated:
            return False
        return user.is_staff or getattr(user, "role", None) == "admin"


class IsEnrollmentParticipant(BasePermission):
    """
    Object-level check for ProgramEnrollment / ProgramExitRequest. Allows the
    mentee owning the enrollment, the program's nest owner, or platform staff.
    """

    def has_permission(self, request, view) -> bool:
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj) -> bool:
        user = request.user
        if user.is_staff:
            return True
        enrollment = obj if isinstance(obj, ProgramEnrollment) else obj.enrollment
        if enrollment.mentee_id == user.id:
            return True
        return enrollment.program.nest.eagle_id == user.id


class ProgramRulesLocked(BasePermission):
    """
    Plan 14.5-01: Block POST/PATCH/PUT/DELETE on objectives + rules once any
    pending or active ProgramEnrollment exists for the program.

    Reads (GET/HEAD/OPTIONS) always allowed — mentees must still see objectives.
    Resolves the program from view.kwargs['program_pk'] (set by router for
    nested ProgramObjective + ProgramObjectiveRule viewsets).
    """

    def has_permission(self, request, view) -> bool:
        from rest_framework.permissions import SAFE_METHODS

        if request.method in SAFE_METHODS:
            return True

        program_id = view.kwargs.get("program_pk") or view.kwargs.get("pk")
        if not program_id:
            return True  # Defer to other permissions for resolution

        # Try to find a ProgramEnrollment that locks the rules.
        locked = ProgramEnrollment.objects.filter(
            program_id=program_id,
            status__in=[
                ProgramEnrollment.Status.PENDING,
                ProgramEnrollment.Status.ACTIVE,
            ],
        ).exists()
        if locked:
            raise ProgramRulesLockedException()
        return True

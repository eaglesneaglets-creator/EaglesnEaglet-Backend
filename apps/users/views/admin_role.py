"""
Admin Role Management — REST surface (plan 18-01).

Endpoints mounted under ``/api/v1/admin-role/``. See PLAN for the full
table. All admin-only endpoints require ``is_admin == True`` (which also
covers stacked-admin Eagles via the User.is_admin property).
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework.response import Response

from ..models_admin import AdminInvite, AdminRoleAudit, AdminRoleRequest
from ..serializers_admin import (
    AdminInviteSerializer,
    AdminRoleAuditSerializer,
    AdminRoleRequestSerializer,
    DecisionNoteSerializer,
    EligibilitySerializer,
    RejectNoteSerializer,
    RevokeAdminSerializer,
    SendInviteSerializer,
    SubmitEOISerializer,
    TeamMemberSerializer,
)
from ..services import admin_role as svc

User = get_user_model()


class IsPlatformAdmin(BasePermission):
    """Allow only users where User.is_admin is True (covers stacked Eagles)."""

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and u.is_admin)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _ok(payload, code=status.HTTP_200_OK):
    return Response({"success": True, "data": payload}, status=code)


def _err(message: str, code: str, http=status.HTTP_400_BAD_REQUEST, **extra):
    body = {
        "success": False,
        "error": {"code": http, "type": code, "message": message},
    }
    if extra:
        body["error"]["details"] = extra
    return Response(body, status=http)


def _map_error(e: svc.AdminRoleError):
    """Translate service errors to HTTP responses."""
    if isinstance(e, svc.LastAdminError):
        return _err(str(e), code=e.code, http=status.HTTP_409_CONFLICT)
    if isinstance(e, svc.PendingReviewError):
        return _err(str(e), code=e.code, http=status.HTTP_409_CONFLICT,
                    review_ids=e.review_ids)
    if isinstance(e, svc.AlreadyAdminError):
        return _err(str(e), code=e.code, http=status.HTTP_409_CONFLICT)
    if isinstance(e, svc.IneligibleError):
        return _err(str(e), code=e.code, http=status.HTTP_403_FORBIDDEN,
                    reasons=e.reasons)
    if isinstance(e, svc.InviteError):
        code_to_http = {
            "invalid": status.HTTP_410_GONE,
            "email_mismatch": status.HTTP_403_FORBIDDEN,
        }
        return _err(str(e), code=e.code, http=code_to_http.get(e.code, 400))
    return _err(str(e), code="admin_role_error", http=status.HTTP_400_BAD_REQUEST)


# ─── Eligibility / self EOI ──────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def eligibility_view(request):
    payload = svc.get_eligibility(request.user)
    return _ok(EligibilitySerializer(payload).data)


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def requests_collection_view(request):
    """
    GET  /admin-role/requests/   -> admin only, list (filter ?status=...)
    POST /admin-role/requests/   -> any eligible mentor, submit EOI
    """
    if request.method == "POST":
        ser = SubmitEOISerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            req = svc.submit_eoi(request.user, ser.validated_data["reason"])
        except svc.AdminRoleError as e:
            return _map_error(e)
        return _ok(AdminRoleRequestSerializer(req).data, code=status.HTTP_201_CREATED)

    # GET — admin only
    if not request.user.is_admin:
        return _err("Admin only.", code="forbidden", http=status.HTTP_403_FORBIDDEN)

    status_filter = request.query_params.get("status")
    qs = AdminRoleRequest.objects.select_related("user", "decided_by").all()
    if status_filter and status_filter != "all":
        qs = qs.filter(status=status_filter)
    return _ok(AdminRoleRequestSerializer(qs, many=True).data)


@api_view(["GET", "DELETE"])
@permission_classes([IsAuthenticated])
def my_request_view(request):
    """
    GET    /admin-role/requests/me/  -> current user's most recent request
    DELETE /admin-role/requests/me/  -> withdraw the current user's pending request
    """
    if request.method == "DELETE":
        try:
            req = svc.withdraw_eoi(request.user)
        except svc.AdminRoleError:
            return _err("No pending request.", code="not_found",
                        http=status.HTTP_404_NOT_FOUND)
        return _ok(AdminRoleRequestSerializer(req).data)

    req = (
        AdminRoleRequest.objects
        .select_related("user", "decided_by")
        .filter(user=request.user)
        .order_by("-created_at")
        .first()
    )
    if req is None:
        return _ok(None)
    return _ok(AdminRoleRequestSerializer(req).data)


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsPlatformAdmin])
def approve_request_view(request, request_id):
    ser = DecisionNoteSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    try:
        req = svc.approve_eoi(
            actor=request.user,
            request_id=request_id,
            note=ser.validated_data.get("note", ""),
        )
    except AdminRoleRequest.DoesNotExist:
        return _err("Request not found.", code="not_found",
                    http=status.HTTP_404_NOT_FOUND)
    except svc.AdminRoleError as e:
        return _map_error(e)
    return _ok(AdminRoleRequestSerializer(req).data)


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsPlatformAdmin])
def reject_request_view(request, request_id):
    ser = RejectNoteSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    try:
        req = svc.reject_eoi(
            actor=request.user,
            request_id=request_id,
            note=ser.validated_data["note"],
        )
    except AdminRoleRequest.DoesNotExist:
        return _err("Request not found.", code="not_found",
                    http=status.HTTP_404_NOT_FOUND)
    except svc.AdminRoleError as e:
        return _map_error(e)
    return _ok(AdminRoleRequestSerializer(req).data)


# ─── Invites ─────────────────────────────────────────────────────────────────

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated, IsPlatformAdmin])
def invites_collection_view(request):
    if request.method == "POST":
        ser = SendInviteSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            invite, raw_token = svc.send_invite(
                actor=request.user,
                email=ser.validated_data["email"],
                message=ser.validated_data.get("message", ""),
            )
        except svc.AdminRoleError as e:
            return _map_error(e)
        # Return the raw token ONCE so the admin can copy the accept link.
        # Subsequent fetches of /invites/ never expose it again.
        payload = AdminInviteSerializer(invite).data
        payload["accept_token_once"] = raw_token
        payload["accept_url_once"] = (
            f"{request.scheme}://{request.get_host()}/admin-role/accept/{raw_token}"
        )
        return _ok(payload, code=status.HTTP_201_CREATED)

    status_filter = request.query_params.get("status")
    qs = AdminInvite.objects.select_related("invited_by", "accepted_by").all()
    if status_filter and status_filter != "all":
        qs = qs.filter(status=status_filter)
    return _ok(AdminInviteSerializer(qs, many=True).data)


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsPlatformAdmin])
def revoke_invite_view(request, invite_id):
    try:
        invite = svc.revoke_invite(actor=request.user, invite_id=invite_id)
    except AdminInvite.DoesNotExist:
        return _err("Invite not found.", code="not_found",
                    http=status.HTTP_404_NOT_FOUND)
    except svc.AdminRoleError as e:
        return _map_error(e)
    return _ok(AdminInviteSerializer(invite).data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def accept_invite_view(request, token):
    try:
        invite = svc.accept_invite(user=request.user, token=token)
    except svc.AdminRoleError as e:
        return _map_error(e)
    return _ok(AdminInviteSerializer(invite).data)


# ─── Team / revocation ──────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated, IsPlatformAdmin])
def team_view(request):
    """Return current admin pool with promotion provenance per user."""
    admins = User.objects.filter(is_platform_staff=True).order_by("first_name", "email")

    # Pre-fetch latest granted audit per admin to enrich the list.
    latest_grants = {}
    grant_rows = (
        AdminRoleAudit.objects
        .filter(action=AdminRoleAudit.Action.GRANTED, target__in=admins)
        .order_by("target_id", "-created_at")
        .values("target_id", "source", "created_at")
    )
    seen = set()
    for row in grant_rows:
        if row["target_id"] in seen:
            continue
        seen.add(row["target_id"])
        latest_grants[row["target_id"]] = row

    members = []
    for admin in admins:
        grant = latest_grants.get(admin.id, {})
        members.append({
            "id": admin.id,
            "email": admin.email,
            "full_name": admin.full_name,
            "role": admin.role,
            "is_platform_staff": admin.is_platform_staff,
            "is_stacked": admin.is_stacked_admin,
            "promoted_at": grant.get("created_at"),
            "promoted_source": grant.get("source"),
            "avatar": (
                admin.avatar.url if admin.avatar
                else (admin.profile_picture_url or None)
            ),
        })
    return _ok(TeamMemberSerializer(members, many=True).data)


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsPlatformAdmin])
def revoke_team_member_view(request, user_id):
    if str(request.user.id) == str(user_id):
        return _err(
            "Use the self-revoke endpoint to revoke your own admin.",
            code="use_self_revoke",
            http=status.HTTP_409_CONFLICT,
        )
    ser = RevokeAdminSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    try:
        svc.revoke_admin(
            actor=request.user,
            target_id=user_id,
            reason=ser.validated_data["reason"],
        )
    except User.DoesNotExist:
        return _err("User not found.", code="not_found",
                    http=status.HTTP_404_NOT_FOUND)
    except svc.AdminRoleError as e:
        return _map_error(e)
    return _ok({"revoked": True})


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsPlatformAdmin])
def self_revoke_view(request):
    reason = (request.data or {}).get("reason", "")
    try:
        svc.self_revoke_admin(user=request.user, reason=reason)
    except svc.AdminRoleError as e:
        return _map_error(e)
    return _ok({"revoked": True})


# ─── Audit feed ──────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated, IsPlatformAdmin])
def audit_view(request):
    """Last 200 entries; pagination can be added if the table grows."""
    qs = (
        AdminRoleAudit.objects
        .select_related("actor", "target")
        .order_by("-created_at")[:200]
    )
    return _ok(AdminRoleAuditSerializer(qs, many=True).data)

"""
Mentor application views (plan 16-01).

Applicant endpoints (owner-scoped) + admin-queue endpoints (admin-only),
delegating lifecycle to services/mentor_application.py. Responses use the
standard { success, data } / { success, error } wrapper.
"""

import logging

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from core.permissions.roles import IsAdmin
from ..models_mentor_app import MentorApplication
from ..serializers_mentor_app import (
    MentorApplicationSerializer,
    MentorApplicationAuditSerializer,
)
from ..services import mentor_application as svc

logger = logging.getLogger(__name__)


def _ok(data, code=status.HTTP_200_OK):
    return Response({"success": True, "data": data}, status=code)


def _err(message, code=status.HTTP_400_BAD_REQUEST, err_type="ValidationError"):
    return Response(
        {"success": False, "error": {"code": code, "type": err_type, "message": message}},
        status=code,
    )


class MentorApplicationView(APIView):
    """GET own application (+ eligibility); POST submit a new application."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        app = (
            MentorApplication.objects
            .filter(user=request.user)
            .order_by("-created_at")
            .first()
        )
        # Surface post-rejection cooldown so the FE can render a countdown
        # without parsing the error message of a failed POST.
        cooldown_until = None
        if app and app.status == MentorApplication.Status.REJECTED and app.reviewed_at:
            from datetime import timedelta
            from django.conf import settings as dj_settings
            from django.utils import timezone
            days = int(getattr(dj_settings, "MENTOR_APPLICATION_REJECT_COOLDOWN_DAYS", 30))
            candidate = app.reviewed_at + timedelta(days=days)
            if timezone.now() < candidate:
                cooldown_until = candidate
        return _ok({
            "eligible": svc.is_eligible(request.user),
            "application": MentorApplicationSerializer(app).data if app else None,
            "cooldown_until": cooldown_until.isoformat() if cooldown_until else None,
        })

    def post(self, request):
        try:
            app = svc.submit(user=request.user)
        except svc.MentorApplicationError as exc:
            return _err(str(exc))
        return _ok(MentorApplicationSerializer(app).data, code=status.HTTP_201_CREATED)


class MentorApplicationWithdrawView(APIView):
    """POST — applicant withdraws their own pending application."""

    permission_classes = [IsAuthenticated]

    def post(self, request, application_id):
        try:
            app = svc.withdraw(user=request.user, application_id=application_id)
        except MentorApplication.DoesNotExist:
            return _err("Application not found.", status.HTTP_404_NOT_FOUND, "NotFound")
        except svc.MentorApplicationError as exc:
            return _err(str(exc))
        return _ok(MentorApplicationSerializer(app).data)


class AdminMentorApplicationListView(APIView):
    """GET — admin queue of mentor applications (filter by ?status=)."""

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        qs = MentorApplication.objects.select_related("user", "reviewed_by")
        status_filter = request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)
        else:
            qs = qs.filter(status=MentorApplication.Status.SUBMITTED)
        return _ok(MentorApplicationSerializer(qs.order_by("-created_at"), many=True).data)


class AdminMentorApplicationDecisionView(APIView):
    """POST approve/reject a submitted application. Action via URL suffix."""

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, application_id, action):
        try:
            if action == "approve":
                app = svc.approve(
                    actor=request.user,
                    application_id=application_id,
                    note=request.data.get("note", ""),
                )
            elif action == "reject":
                app = svc.reject(
                    actor=request.user,
                    application_id=application_id,
                    reason=request.data.get("reason", ""),
                )
            else:
                return _err("Unknown action.", status.HTTP_404_NOT_FOUND, "NotFound")
        except MentorApplication.DoesNotExist:
            return _err("Application not found.", status.HTTP_404_NOT_FOUND, "NotFound")
        except svc.MentorApplicationError as exc:
            return _err(str(exc))
        return _ok({
            "application": MentorApplicationSerializer(app).data,
            "audit": MentorApplicationAuditSerializer(
                app.audit_entries.all(), many=True
            ).data,
        })

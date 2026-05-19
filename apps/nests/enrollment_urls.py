"""
Top-level URLs for ProgramEnrollment + ProgramExitRequest (plan 14-02).

Mounted under /api/v1/program-enrollments/ and /api/v1/program-exit-requests/.
Kept as a separate module from apps/nests/urls.py so the project root URLconf
can include them at the top level (rather than nesting them under /nests/).
"""

from django.urls import path

from .views import ProgramEnrollmentViewSet, ProgramExitRequestViewSet


enrollment_list = ProgramEnrollmentViewSet.as_view({"get": "list"})
enrollment_detail = ProgramEnrollmentViewSet.as_view({"get": "retrieve"})
enrollment_my_active = ProgramEnrollmentViewSet.as_view({"get": "my_active"})
enrollment_my_requests = ProgramEnrollmentViewSet.as_view({"get": "my_requests"})
enrollment_approve = ProgramEnrollmentViewSet.as_view({"post": "approve"})
enrollment_reject = ProgramEnrollmentViewSet.as_view({"post": "reject"})
enrollment_release = ProgramEnrollmentViewSet.as_view({"post": "release"})
enrollment_complete = ProgramEnrollmentViewSet.as_view({"post": "complete"})
enrollment_opt_out = ProgramEnrollmentViewSet.as_view({"post": "opt_out_request"})

exit_request_list = ProgramExitRequestViewSet.as_view({"get": "list"})
exit_request_decide = ProgramExitRequestViewSet.as_view({"post": "decide"})


enrollment_urlpatterns = [
    # Static routes BEFORE <uuid:pk> so they don't get captured.
    path("my-active/", enrollment_my_active, name="program-enrollment-my-active"),
    path("my-requests/", enrollment_my_requests, name="program-enrollment-my-requests"),
    path("", enrollment_list, name="program-enrollment-list"),
    path("<uuid:pk>/", enrollment_detail, name="program-enrollment-detail"),
    path("<uuid:pk>/approve/", enrollment_approve, name="program-enrollment-approve"),
    path("<uuid:pk>/reject/", enrollment_reject, name="program-enrollment-reject"),
    path("<uuid:pk>/release/", enrollment_release, name="program-enrollment-release"),
    path("<uuid:pk>/complete/", enrollment_complete, name="program-enrollment-complete"),
    path("<uuid:pk>/opt-out-request/", enrollment_opt_out, name="program-enrollment-opt-out"),
]


exit_request_urlpatterns = [
    path("", exit_request_list, name="program-exit-request-list"),
    path("<uuid:pk>/decide/", exit_request_decide, name="program-exit-request-decide"),
]

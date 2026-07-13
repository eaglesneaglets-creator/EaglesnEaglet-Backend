"""URL routes for Admin Role Management (plan 18-01).

Mounted at ``/api/v1/admin-role/``.
"""

from django.urls import path

from .views import admin_role as views

app_name = "users_admin_role"

urlpatterns = [
    path("eligibility/", views.eligibility_view, name="eligibility"),

    path("requests/", views.requests_collection_view, name="requests"),
    path("requests/me/", views.my_request_view, name="my-request"),
    path("requests/<uuid:request_id>/approve/", views.approve_request_view, name="approve"),
    path("requests/<uuid:request_id>/reject/", views.reject_request_view, name="reject"),

    path("invites/", views.invites_collection_view, name="invites"),
    path("invites/<uuid:invite_id>/revoke/", views.revoke_invite_view, name="revoke-invite"),
    path("invites/accept/<str:token>/", views.accept_invite_view, name="accept-invite"),

    path("team/", views.team_view, name="team"),
    path("team/<uuid:user_id>/revoke/", views.revoke_team_member_view, name="revoke-member"),
    path("me/revoke/", views.self_revoke_view, name="self-revoke"),
    path(
        "me/transfer-superadmin/",
        views.transfer_superadmin_view,
        name="transfer-superadmin",
    ),

    path("audit/", views.audit_view, name="audit"),
]

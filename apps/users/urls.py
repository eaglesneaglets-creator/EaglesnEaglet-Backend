"""
User App URL Configuration

URL routes for authentication, user management, and KYC.
"""

from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    # =========================================================================
    # AUTHENTICATION
    # =========================================================================
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('token/refresh/', views.CustomTokenRefreshView.as_view(), name='token-refresh'),

    # =========================================================================
    # GOOGLE OAUTH
    # =========================================================================
    path('google/login/', views.GoogleOAuthLoginView.as_view(), name='google-login'),
    path('google/callback/', views.GoogleOAuthCallbackView.as_view(), name='google-callback'),

    # =========================================================================
    # EMAIL VERIFICATION
    # =========================================================================
    path('email/verify/', views.EmailVerificationView.as_view(), name='email-verify'),
    path('email/resend/', views.ResendVerificationView.as_view(), name='email-resend'),

    # =========================================================================
    # PASSWORD MANAGEMENT
    # =========================================================================
    path('password/reset/', views.PasswordResetRequestView.as_view(), name='password-reset'),
    path('password/reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password/change/', views.PasswordChangeView.as_view(), name='password-change'),

    # =========================================================================
    # CURRENT USER
    # =========================================================================
    path('me/', views.CurrentUserView.as_view(), name='current-user'),

    # =========================================================================
    # MENTOR KYC
    # =========================================================================
    path('kyc/', views.MentorKYCView.as_view(), name='mentor-kyc'),
    path('kyc/step/<int:step_number>/', views.MentorKYCStepView.as_view(), name='mentor-kyc-step'),
    path('kyc/submit/', views.MentorKYCSubmitView.as_view(), name='mentor-kyc-submit'),
    path('kyc/upload/government-id/', views.UploadGovernmentIDView.as_view(), name='upload-government-id'),
    path('kyc/upload/recommendation/', views.UploadRecommendationView.as_view(), name='upload-recommendation'),

    # =========================================================================
    # EAGLET (MENTEE) PROFILE (Legacy)
    # =========================================================================
    path('eaglet/profile/', views.EagletProfileView.as_view(), name='eaglet-profile'),
    path('eaglet/onboarding/', views.EagletOnboardingView.as_view(), name='eaglet-onboarding'),
    path('eaglet/onboarding/skip/', views.EagletSkipOnboardingView.as_view(), name='eaglet-skip-onboarding'),

    # =========================================================================
    # NEW PROFILE/KYC ROUTES (PM Requirements - Both roles need approval)
    # =========================================================================
    # Mentor (Eagle) Profile
    path('mentor-profile/', views.MentorProfileView.as_view(), name='mentor-profile'),

    # Mentee (Eaglet) Profile
    path('mentee-profile/', views.MenteeProfileView.as_view(), name='mentee-profile'),

    # Profile Submission (works for both roles)
    path('profile/submit/', views.ProfileSubmitView.as_view(), name='profile-submit'),

    # File Uploads (works for both roles)
    path('upload/picture/', views.UploadDisplayPictureView.as_view(), name='upload-picture'),
    path('upload/cv/', views.UploadCVView.as_view(), name='upload-cv'),

    # =========================================================================
    # ADMIN KYC MANAGEMENT
    # =========================================================================
    path('admin/stats/', views.AdminDashboardStatsView.as_view(), name='admin-stats'),
    path('admin/kyc/', views.AdminKYCListView.as_view(), name='admin-kyc-list'),
    path('admin/kyc/<uuid:kyc_id>/', views.AdminKYCDetailView.as_view(), name='admin-kyc-detail'),
    path('admin/kyc/<uuid:kyc_id>/approve/', views.AdminKYCApproveView.as_view(), name='admin-kyc-approve'),
    path('admin/kyc/<uuid:kyc_id>/reject/', views.AdminKYCRejectView.as_view(), name='admin-kyc-reject'),
    path('admin/kyc/<uuid:kyc_id>/request-changes/', views.AdminKYCRequestChangesView.as_view(), name='admin-kyc-request-changes'),
    path('admin/kyc/<uuid:kyc_id>/notes/', views.AdminKYCNotesView.as_view(), name='admin-kyc-notes'),
]

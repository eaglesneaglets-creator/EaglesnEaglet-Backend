"""
Donations URL Configuration
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AdminDonationStatsView,
    CampaignViewSet,
    DonationStatusView,
    HubtelPaymentCallbackView,
    InitiateDonationView,
    MyDonationsView,
    OtpSendView,
    OtpVerifyView,
)

router = DefaultRouter()
router.register(r"campaigns", CampaignViewSet, basename="campaign")

urlpatterns = [
    path("", include(router.urls)),
    path("otp/send/", OtpSendView.as_view(), name="donation-otp-send"),
    path("otp/verify/", OtpVerifyView.as_view(), name="donation-otp-verify"),
    path("initiate/", InitiateDonationView.as_view(), name="donation-initiate"),
    path("callback/payment/", HubtelPaymentCallbackView.as_view(), name="donation-callback"),
    path("status/<str:donation_id>/", DonationStatusView.as_view(), name="donation-status"),
    path("my-donations/", MyDonationsView.as_view(), name="my-donations"),
    path("admin/stats/", AdminDonationStatsView.as_view(), name="donation-admin-stats"),
]

"""
Mentor Availability Schedule Views

Auto-extracted from monolithic views.py during Phase 11.5-04 split.
"""

import requests
import logging
from urllib.parse import urlencode

from django.conf import settings
from django.db import models
from django.shortcuts import redirect
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from core.permissions.roles import IsEagle, IsEaglet, IsAdmin
from core.throttling import BurstRateThrottle, LoginRateThrottle, RegisterRateThrottle, PasswordResetThrottle

logger = logging.getLogger(__name__)

from ..models import User, MentorKYC, MenteeKYC, EagletProfile
from ..serializers import (
    CustomTokenObtainPairSerializer,
    UserSerializer,
    UserRegistrationSerializer,
    PasswordChangeSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer,
    ResendVerificationSerializer,
    MentorKYCSerializer,
    MentorKYCStep1Serializer,
    MentorKYCStep2Serializer,
    MentorKYCStep3Serializer,
    MentorKYCStep4Serializer,
    EagletProfileSerializer,
    EagletOnboardingSerializer,
    EagletCompleteOnboardingSerializer,
    MentorKYCListSerializer,
    MentorKYCDetailSerializer,
    KYCApprovalSerializer,
    KYCRejectionSerializer,
    KYCRequestChangesSerializer,
    AdminInternalNoteSerializer,
    MentorKYCNewSerializer,
    MentorKYCNewUpdateSerializer,
    MenteeKYCSerializer,
    MenteeKYCUpdateSerializer,
    MenteeKYCListSerializer,
    MenteeKYCDetailSerializer,
)
from ..validators import validate_cv_file, validate_image_file


class MentorAvailabilityView(APIView):
    """List and create availability slots for the authenticated Eagle."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from ..models import MentorAvailability
        from ..serializers import MentorAvailabilitySerializer
        slots = MentorAvailability.objects.filter(mentor=request.user, is_active=True)
        serializer = MentorAvailabilitySerializer(slots, many=True)
        return Response({'success': True, 'data': serializer.data})

    def post(self, request):
        from ..models import MentorAvailability
        from ..serializers import MentorAvailabilitySerializer
        if request.user.role != 'eagle':
            return Response({'success': False, 'error': {'message': 'Only Eagles can set availability.'}}, status=403)
        serializer = MentorAvailabilitySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(mentor=request.user)
        return Response({'success': True, 'data': serializer.data}, status=201)

class MentorAvailabilityDetailView(APIView):
    """Delete a specific availability slot."""
    permission_classes = [IsAuthenticated]

    def delete(self, request, slot_id):
        from ..models import MentorAvailability
        try:
            slot = MentorAvailability.objects.get(id=slot_id, mentor=request.user)
        except MentorAvailability.DoesNotExist:
            return Response({'success': False, 'error': {'message': 'Slot not found.'}}, status=404)
        slot.delete()
        return Response({'success': True}, status=204)

class PublicMentorAvailabilityView(APIView):
    """Public read-only view of a mentor's availability (for Eaglets)."""
    permission_classes = []  # AllowAny

    def get(self, request, user_id):
        from ..models import MentorAvailability
        from ..serializers import MentorAvailabilitySerializer
        slots = MentorAvailability.objects.filter(mentor_id=user_id, is_active=True)
        serializer = MentorAvailabilitySerializer(slots, many=True)
        return Response({'success': True, 'data': serializer.data})


# =============================================================================
# Account Settings (Phase 11-02)
# =============================================================================

import secrets
from datetime import timedelta

"""
Google OAuth Views

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

from .auth import _set_auth_cookies, _clear_auth_cookies
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


class GoogleOAuthLoginView(APIView):
    """
    Initiate Google OAuth 2.0 login flow.
    Redirects user to Google consent screen.

    The state parameter carries a JSON payload with a random nonce and the
    requested role, encoded in base64. The nonce is stored in the Django cache
    and verified in the callback to prevent CSRF and replay attacks.

    GET /api/v1/auth/google/login/
    """

    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]

    def get(self, request):
        import json
        import base64
        import secrets as _secrets
        from django.core.cache import cache

        client_id = getattr(settings, 'GOOGLE_OAUTH2_CLIENT_ID', '')
        redirect_uri = getattr(settings, 'GOOGLE_OAUTH2_REDIRECT_URI', '')

        if not client_id:
            return Response({
                'success': False,
                'error': {
                    'code': 500,
                    'type': 'ConfigurationError',
                    'message': 'Google OAuth is not configured.'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Get role from query params
        role = request.GET.get('role', 'eaglet')
        if role not in ['eagle', 'eaglet']:
            role = 'eaglet'

        # Generate CSRF nonce and store in cache for verification
        csrf_nonce = _secrets.token_urlsafe(32)
        security = getattr(settings, 'SECURITY', {})
        state_timeout = security.get('OAUTH_STATE_TIMEOUT_SECONDS', 600)

        cache_key = f'oauth_state:{csrf_nonce}'
        cache.set(cache_key, {'role': role, 'nonce': csrf_nonce}, timeout=state_timeout)

        # Encode nonce + role into the state parameter (base64 JSON)
        state_data = json.dumps({'nonce': csrf_nonce, 'role': role})
        state_encoded = base64.urlsafe_b64encode(state_data.encode()).decode()

        # Build Google OAuth URL
        params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'email profile openid',
            'access_type': 'offline',
            'prompt': 'consent',
            'state': state_encoded,
        }

        google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

        return Response({
            'success': True,
            'data': {
                'auth_url': google_auth_url
            }
        })

class GoogleOAuthCallbackView(APIView):
    """
    Handle Google OAuth 2.0 callback.
    Exchange code for tokens, create/login user, return JWT.

    POST /api/v1/auth/google/callback/
    """

    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]

    def post(self, request):
        import json
        import base64
        from django.core.cache import cache

        code = request.data.get('code')
        state_encoded = request.data.get('state', '')

        if not code:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'MissingCode',
                    'message': 'Authorization code is required.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify OAuth state parameter (CSRF + replay protection)
        role = 'eaglet'  # Default fallback
        if state_encoded:
            try:
                state_data = json.loads(base64.urlsafe_b64decode(state_encoded))
                nonce = state_data.get('nonce', '')
                role = state_data.get('role', 'eaglet')

                # Validate nonce exists in cache
                cache_key = f'oauth_state:{nonce}'
                cached_state = cache.get(cache_key)
                if not cached_state or cached_state.get('nonce') != nonce:
                    logger.warning("OAuth state nonce invalid or expired")
                    return Response({
                        'success': False,
                        'error': {
                            'code': 400,
                            'type': 'InvalidState',
                            'message': 'OAuth session expired or invalid. Please try again.'
                        }
                    }, status=status.HTTP_400_BAD_REQUEST)

                # Delete nonce to prevent replay attacks
                cache.delete(cache_key)

            except (json.JSONDecodeError, ValueError, Exception) as exc:
                logger.warning("OAuth state decode failed: %s", exc)
                return Response({
                    'success': False,
                    'error': {
                        'code': 400,
                        'type': 'InvalidState',
                        'message': 'OAuth session expired or invalid. Please try again.'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # No state parameter — reject; state is required for CSRF protection.
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'MissingState',
                    'message': 'OAuth state parameter is required. Please try again.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate role
        if role not in ['eagle', 'eaglet']:
            role = 'eaglet'

        client_id = getattr(settings, 'GOOGLE_OAUTH2_CLIENT_ID', '')
        client_secret = getattr(settings, 'GOOGLE_OAUTH2_CLIENT_SECRET', '')
        redirect_uri = getattr(settings, 'GOOGLE_OAUTH2_REDIRECT_URI', '')

        if not all([client_id, client_secret]):
            return Response({
                'success': False,
                'error': {
                    'code': 500,
                    'type': 'ConfigurationError',
                    'message': 'Google OAuth is not configured.'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Exchange code for tokens
        try:
            token_response = requests.post(
                'https://oauth2.googleapis.com/token',
                data={
                    'code': code,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'redirect_uri': redirect_uri,
                    'grant_type': 'authorization_code',
                },
                timeout=10
            )

            if token_response.status_code != 200:
                logger.error("Google token exchange failed: %s", token_response.text)
                return Response({
                    'success': False,
                    'error': {
                        'code': 400,
                        'type': 'TokenExchangeFailed',
                        'message': 'Failed to authenticate with Google. Please try again.'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            token_data = token_response.json()
            access_token = token_data.get('access_token')

        except requests.RequestException as e:
            logger.error("Google OAuth request failed: %s", e)
            return Response({
                'success': False,
                'error': {
                    'code': 500,
                    'type': 'NetworkError',
                    'message': 'Failed to connect to Google. Please try again.'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Get user info from Google
        try:
            user_info_response = requests.get(
                'https://www.googleapis.com/oauth2/v2/userinfo',
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10
            )

            if user_info_response.status_code != 200:
                logger.error("Google user info failed: %s", user_info_response.text)
                return Response({
                    'success': False,
                    'error': {
                        'code': 400,
                        'type': 'UserInfoFailed',
                        'message': 'Failed to get user information from Google.'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            user_info = user_info_response.json()

        except requests.RequestException as e:
            logger.error("Google user info request failed: %s", e)
            return Response({
                'success': False,
                'error': {
                    'code': 500,
                    'type': 'NetworkError',
                    'message': 'Failed to get user information. Please try again.'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Extract user data
        email = user_info.get('email')
        first_name = user_info.get('given_name', '')
        last_name = user_info.get('family_name', '')
        google_id = user_info.get('id')
        picture = user_info.get('picture')

        if not email:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoEmail',
                    'message': 'Email is required. Please ensure your Google account has an email.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user exists
        try:
            user = User.objects.get(email=email)
            is_new_user = False

            # Check if user was created with different auth method
            if not user.google_id:
                # Link Google account to existing user
                user.google_id = google_id
                if picture and not user.profile_picture_url:
                    user.profile_picture_url = picture
                user.save(update_fields=['google_id', 'profile_picture_url'] if picture else ['google_id'])

        except User.DoesNotExist:
            # Create new user
            user = User.objects.create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                role=role,
                google_id=google_id,
                is_email_verified=True,  # Email verified by Google
            )

            if picture:
                user.profile_picture_url = picture
                user.save(update_fields=['profile_picture_url'])

            is_new_user = True

            # Create role-specific profile
            if role == 'eagle':
                MentorKYC.objects.create(user=user)
            else:
                EagletProfile.objects.create(user=user)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        # Build response
        response_data = {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data,
            'is_new_user': is_new_user,
        }

        # Add role-specific data
        if user.is_eagle:
            try:
                kyc = MentorKYC.objects.get(user=user)
                response_data['user']['kyc_status'] = kyc.status
                response_data['user']['kyc_completion'] = kyc.completion_percentage
            except MentorKYC.DoesNotExist:
                response_data['user']['kyc_status'] = None
                response_data['user']['kyc_completion'] = 0

        if user.is_eaglet:
            try:
                profile = EagletProfile.objects.get(user=user)
                response_data['user']['profile_completeness'] = profile.profile_completeness
                response_data['user']['onboarding_completed'] = profile.onboarding_completed
            except EagletProfile.DoesNotExist:
                response_data['user']['profile_completeness'] = 0
                response_data['user']['onboarding_completed'] = False

        api_response = Response({
            'success': True,
            'data': response_data
        })
        _set_auth_cookies(api_response, str(refresh.access_token), str(refresh))
        return api_response


# =============================================================================
# ADMIN KYC MANAGEMENT VIEWS
# =============================================================================

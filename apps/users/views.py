"""
User Views

Views for authentication, user management, and KYC.
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

from .models import User, MentorKYC, MenteeKYC, EagletProfile
from .serializers import (
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
    # Admin serializers
    MentorKYCListSerializer,
    MentorKYCDetailSerializer,
    KYCApprovalSerializer,
    KYCRejectionSerializer,
    KYCRequestChangesSerializer,
    AdminInternalNoteSerializer,
    # NEW: Profile/KYC serializers (PM requirements)
    MentorKYCNewSerializer,
    MentorKYCNewUpdateSerializer,
    MenteeKYCSerializer,
    MenteeKYCUpdateSerializer,
    MenteeKYCListSerializer,
    MenteeKYCDetailSerializer,
)
from .validators import validate_cv_file, validate_image_file


# =============================================================================
# AUTHENTICATION VIEWS
# =============================================================================

# =============================================================================
# COOKIE HELPERS — JWT httpOnly cookie management
# =============================================================================

def _set_auth_cookies(response, access_token: str, refresh_token: str = None) -> None:
    """
    Attach JWT tokens as httpOnly cookies to a DRF Response.

    SameSite=None is required for cross-origin requests (frontend on Vercel,
    backend on Railway). SameSite=None requires Secure=True (HTTPS only).
    In local dev (DEBUG=True) we use SameSite=Lax + Secure=False since
    localhost is same-site and doesn't support HTTPS easily.
    """
    is_secure = not settings.DEBUG
    samesite = 'None' if is_secure else 'Lax'

    response.set_cookie(
        key='access_token',
        value=str(access_token),
        httponly=True,
        secure=is_secure,
        samesite=samesite,
        max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
        path='/',
    )
    if refresh_token is not None:
        response.set_cookie(
            key='refresh_token',
            value=str(refresh_token),
            httponly=True,
            secure=is_secure,
            samesite=samesite,
            max_age=int(settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()),
            path='/',
        )


def _clear_auth_cookies(response) -> None:
    """Delete both JWT cookies on logout."""
    is_secure = not settings.DEBUG
    samesite = 'None' if is_secure else 'Lax'
    response.delete_cookie('access_token', path='/', samesite=samesite)
    response.delete_cookie('refresh_token', path='/', samesite=samesite)


class RegisterView(APIView):
    """
    User registration endpoint.

    POST /api/v1/auth/register/
    """

    permission_classes = [AllowAny]
    throttle_classes = [RegisterRateThrottle]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Track email sending status
        email_sent = False
        email_error = None

        # Try to send verification email
        try:
            from .tasks import send_verification_email

            # Try async first (Celery)
            try:
                send_verification_email.delay(str(user.id))
                email_sent = True
            except Exception as celery_error:
                # Celery not available, try synchronous send
                logger.warning(f"Celery not available, trying sync email: {celery_error}")
                try:
                    send_verification_email(str(user.id))
                    email_sent = True
                except Exception as sync_error:
                    logger.error(f"Sync email send failed: {sync_error}")
                    email_error = str(sync_error)
        except ImportError as e:
            logger.error(f"Could not import send_verification_email: {e}")
            email_error = "Email service not configured"

        return Response({
            'success': True,
            'data': {
                'user': UserSerializer(user).data,
                'email_sent': email_sent,
                'message': 'Registration successful. Please check your email to verify your account.' if email_sent
                           else 'Registration successful, but we could not send the verification email. Please use the resend option.',
            }
        }, status=status.HTTP_201_CREATED)


class LoginView(TokenObtainPairView):
    """
    User login endpoint using JWT.

    POST /api/v1/auth/login/
    """

    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [LoginRateThrottle]

    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)

            # Wrap response in standard format
            if response.status_code == 200:
                # Extract tokens before removing them from the response body.
                # Tokens are delivered via httpOnly cookies — never in the JSON body.
                access = response.data.get('access')
                refresh = response.data.get('refresh')
                user_data = response.data.get('user', {})

                api_response = Response({
                    'success': True,
                    'data': {
                        'user': user_data,
                        # access token returned in body for WebSocket ?token= param only.
                        # The refresh token is set exclusively via httpOnly cookie below.
                        'access': access,
                    },
                })
                _set_auth_cookies(api_response, access, refresh)
                return api_response
            return response
        except serializers.ValidationError as e:
            # Extract the error message from the ValidationError
            detail = e.detail
            if isinstance(detail, dict):
                message = detail.get('detail', ['Invalid credentials.'])
                if isinstance(message, list):
                    message = message[0] if message else 'Invalid credentials.'
            elif isinstance(detail, list):
                message = detail[0] if detail else 'Invalid credentials.'
            else:
                message = str(detail)

            return Response({
                'success': False,
                'error': {
                    'code': 401,
                    'type': 'AuthenticationFailed',
                    'message': str(message),
                }
            }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"Login error: {e}", exc_info=True)
            return Response({
                'success': False,
                'error': {
                    'code': 500,
                    'type': 'ServerError',
                    'message': 'An unexpected error occurred. Please try again.',
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    """
    Logout and blacklist refresh token.

    POST /api/v1/auth/logout/
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Read refresh token from httpOnly cookie first, fall back to request body
            # for API clients that still send it in the body.
            refresh_token_str = (
                request.COOKIES.get('refresh_token')
                or request.data.get('refresh')
            )
            if refresh_token_str:
                try:
                    token = RefreshToken(refresh_token_str)
                    token.blacklist()
                except Exception:
                    pass  # Expired token still needs cookies cleared

            logout_response = Response({
                'success': True,
                'message': 'Successfully logged out.'
            }, status=status.HTTP_200_OK)
            _clear_auth_cookies(logout_response)
            return logout_response
        except Exception:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidToken',
                    'message': 'Invalid or expired token.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom token refresh view — reads refresh token from httpOnly cookie,
    falls back to request body for API clients.
    Sets new access_token (and rotated refresh_token) as httpOnly cookies.

    POST /api/v1/auth/token/refresh/
    """

    # The refresh endpoint MUST allow unauthenticated requests.
    # Its job is to issue a new access token when the caller only has a
    # valid refresh_token (httpOnly cookie) — no access token is present.
    permission_classes = [AllowAny]
    authentication_classes = []  # Skip JWT auth — we read the refresh cookie ourselves

    def post(self, request, *args, **kwargs):
        # Read refresh token from cookie first, fall back to request body.
        # We call TokenRefreshSerializer directly so we control the input data,
        # avoiding the DRF request._full_data / _data caching issue.
        refresh_token = request.COOKIES.get('refresh_token') or request.data.get('refresh')

        if not refresh_token:
            return Response({
                'success': False,
                'error': {
                    'code': 401,
                    'type': 'TokenRefreshError',
                    'message': 'No refresh token provided. Please log in again.'
                }
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            from rest_framework_simplejwt.serializers import TokenRefreshSerializer
            serializer = TokenRefreshSerializer(data={'refresh': refresh_token})
            serializer.is_valid(raise_exception=True)

            access = serializer.validated_data.get('access')
            rotated_refresh = serializer.validated_data.get('refresh')  # present when ROTATE_REFRESH_TOKENS=True

            # Return only the access token in the body.
            # The refresh token is set exclusively via httpOnly cookie; never in body.
            api_response = Response({
                'success': True,
                'access': str(access),
            })
            _set_auth_cookies(api_response, access, rotated_refresh)
            return api_response

        except (TokenError, InvalidToken):
            return Response({
                'success': False,
                'error': {
                    'code': 401,
                    'type': 'InvalidToken',
                    'message': 'Token is invalid or expired. Please log in again.'
                }
            }, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 401,
                    'type': 'UserNotFound',
                    'message': 'Session expired. Please log in again.'
                }
            }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return Response({
                'success': False,
                'error': {
                    'code': 401,
                    'type': 'TokenRefreshError',
                    'message': 'Unable to refresh token. Please log in again.'
                }
            }, status=status.HTTP_401_UNAUTHORIZED)


# =============================================================================
# EMAIL VERIFICATION VIEWS
# =============================================================================

class EmailVerificationView(APIView):
    """
    Verify email with token.

    POST /api/v1/auth/email/verify/
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']

        try:
            user = User.objects.get(email_verification_token=token)
            if user.verify_email(token):
                return Response({
                    'success': True,
                    'message': 'Email verified successfully. You can now log in.'
                })
            else:
                return Response({
                    'success': False,
                    'error': {
                        'code': 400,
                        'type': 'TokenExpired',
                        'message': 'Verification token has expired. Please request a new one.'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            # Token not found - could be already used or invalid
            # Provide a helpful message that accounts for already-verified scenarios
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidToken',
                    'message': 'This verification link is invalid or has already been used. If you already verified your email, you can log in now.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationView(APIView):
    """
    Resend email verification.

    POST /api/v1/auth/email/resend/
    """

    permission_classes = [AllowAny]
    throttle_classes = [BurstRateThrottle]

    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)

            if user.is_email_verified:
                return Response({
                    'success': False,
                    'error': {
                        'code': 400,
                        'type': 'AlreadyVerified',
                        'message': 'Email is already verified.'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            # Generate new token
            user.generate_email_verification_token()

            # Send verification email asynchronously
            try:
                from .tasks import send_verification_email
                send_verification_email.delay(str(user.id))
            except Exception:
                pass

            return Response({
                'success': True,
                'message': 'Verification email sent. Please check your inbox.'
            })
        except User.DoesNotExist:
            # Don't reveal if email exists or not
            return Response({
                'success': True,
                'message': 'If this email exists, a verification email has been sent.'
            })


# =============================================================================
# PASSWORD MANAGEMENT VIEWS
# =============================================================================

class PasswordResetRequestView(APIView):
    """
    Request password reset.

    POST /api/v1/auth/password/reset/
    """

    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
            user.generate_password_reset_token()

            # Send password reset email asynchronously
            try:
                from .tasks import send_password_reset_email
                send_password_reset_email.delay(str(user.id))
            except Exception:
                pass
        except User.DoesNotExist:
            pass

        # Always return success to prevent email enumeration
        return Response({
            'success': True,
            'message': 'If this email exists, a password reset link has been sent.'
        })


class PasswordResetConfirmView(APIView):
    """
    Confirm password reset.

    POST /api/v1/auth/password/reset/confirm/
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        try:
            user = User.objects.get(password_reset_token=token)
            if user.reset_password(token, new_password):
                return Response({
                    'success': True,
                    'message': 'Password reset successfully. You can now log in.'
                })
            else:
                return Response({
                    'success': False,
                    'error': {
                        'code': 400,
                        'type': 'TokenExpired',
                        'message': 'Password reset token has expired.'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidToken',
                    'message': 'Invalid password reset token.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeView(APIView):
    """
    Change password for authenticated user.

    POST /api/v1/auth/password/change/
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            'success': True,
            'message': 'Password changed successfully.'
        })


# =============================================================================
# CURRENT USER VIEW
# =============================================================================

class CurrentUserView(APIView):
    """
    Get or update current authenticated user.

    GET /api/v1/auth/me/
    PATCH /api/v1/auth/me/
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        data = UserSerializer(user).data

        # Include KYC status for Eagles
        if user.is_eagle:
            kyc = getattr(user, 'mentor_kyc', None)
            if kyc:
                data['kyc_status'] = kyc.status
                data['kyc_completion'] = kyc.completion_percentage
            else:
                # Fallback to direct query if not prefetched
                kyc = MentorKYC.objects.filter(user=user).first()
                data['kyc_status'] = kyc.status if kyc else None
                data['kyc_completion'] = kyc.completion_percentage if kyc else 0

        # Include profile status for Eaglets
        if user.is_eaglet:
            profile = getattr(user, 'eaglet_profile', None)
            if profile:
                data['profile_completeness'] = profile.profile_completeness
                data['onboarding_completed'] = profile.onboarding_completed
            else:
                profile = EagletProfile.objects.filter(user=user).first()
                data['profile_completeness'] = profile.profile_completeness if profile else 0
                data['onboarding_completed'] = profile.onboarding_completed if profile else False

        return Response({
            'success': True,
            'data': data
        })

    def patch(self, request):
        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            'success': True,
            'data': serializer.data
        })


# =============================================================================
# MENTOR KYC VIEWS
# =============================================================================

class MentorKYCView(APIView):
    """
    Get or update mentor KYC application.

    GET /api/v1/auth/kyc/
    PATCH /api/v1/auth/kyc/
    """

    permission_classes = [IsAuthenticated, IsEagle]

    def get(self, request):
        kyc, created = MentorKYC.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': MentorKYCSerializer(kyc).data
        })

    def patch(self, request):
        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to submitted applications
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify a submitted application.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = MentorKYCSerializer(kyc, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            'success': True,
            'data': serializer.data
        })


class MentorKYCStepView(APIView):
    """
    Update a specific KYC step.

    PATCH /api/v1/auth/kyc/step/{step_number}/
    """

    permission_classes = [IsAuthenticated, IsEagle]

    def get_serializer_class(self, step_number):
        """Get the appropriate serializer for the step."""
        serializers = {
            1: MentorKYCStep1Serializer,
            2: MentorKYCStep2Serializer,
            3: MentorKYCStep3Serializer,
            4: MentorKYCStep4Serializer,
        }
        return serializers.get(step_number)

    def patch(self, request, step_number):
        if step_number not in [1, 2, 3, 4]:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStep',
                    'message': 'Step number must be between 1 and 4.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to submitted applications
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify a submitted application.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer_class = self.get_serializer_class(step_number)
        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Save with the appropriate method
        if step_number == 1:
            serializer.save(user=request.user, kyc=kyc)
        else:
            serializer.save(kyc=kyc)

        return Response({
            'success': True,
            'data': MentorKYCSerializer(kyc).data,
            'message': f'Step {step_number} saved successfully.'
        })


class MentorKYCSubmitView(APIView):
    """
    Submit KYC application for review.

    POST /api/v1/auth/kyc/submit/
    """

    permission_classes = [IsAuthenticated, IsEagle]

    def post(self, request):
        try:
            kyc = MentorKYC.objects.get(user=request.user)
        except MentorKYC.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'KYC application not found. Please start the KYC process first.'
                }
            }, status=status.HTTP_404_NOT_FOUND)

        # Check if already submitted
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'AlreadySubmitted',
                    'message': 'Application has already been submitted.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Try to submit
        if kyc.submit():
            # Send confirmation email
            try:
                from .tasks import send_kyc_submitted_email
                send_kyc_submitted_email.delay(str(request.user.id))
            except Exception:
                pass

            return Response({
                'success': True,
                'data': MentorKYCSerializer(kyc).data,
                'message': 'Application submitted successfully. Our team will review it within 2-3 business days.'
            })
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'IncompleteApplication',
                    'message': 'Please complete all required fields before submitting.',
                    'details': {
                        'completion_percentage': kyc.completion_percentage
                    }
                }
            }, status=status.HTTP_400_BAD_REQUEST)


class UploadGovernmentIDView(APIView):
    """
    Upload government ID document.

    POST /api/v1/auth/kyc/upload/government-id/
    """

    permission_classes = [IsAuthenticated, IsEagle]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to submitted applications
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify a submitted application.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        file = request.FILES.get('government_id')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file size (10MB max)
        if file.size > 10 * 1024 * 1024:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'FileTooLarge',
                    'message': 'File size must be less than 10MB.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file type
        allowed_types = ['application/pdf', 'image/jpeg', 'image/png']
        if file.content_type not in allowed_types:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidFileType',
                    'message': 'File must be PDF, JPG, or PNG.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload to Cloudinary and store the secure_url directly
        from core.storage import upload_to_cloudinary
        try:
            result = upload_to_cloudinary(file, 'government_ids')
        except Exception as exc:
            logger.error("Cloudinary upload failed for government_id (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {'code': 503, 'type': 'UploadFailed', 'message': 'File upload failed. Please try again.'}
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        secure_url = result.get('secure_url')
        if secure_url:
            type(kyc).objects.filter(pk=kyc.pk).update(government_id=secure_url)

        return Response({
            'success': True,
            'data': {
                'government_id': secure_url
            },
            'message': 'Government ID uploaded successfully.'
        })


class UploadRecommendationView(APIView):
    """
    Upload recommendation letter.

    POST /api/v1/auth/kyc/upload/recommendation/
    """

    permission_classes = [IsAuthenticated, IsEagle]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to submitted applications
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify a submitted application.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        file = request.FILES.get('recommendation_letter')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file size (10MB max)
        if file.size > 10 * 1024 * 1024:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'FileTooLarge',
                    'message': 'File size must be less than 10MB.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file type
        allowed_types = ['application/pdf', 'application/msword',
                         'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        if file.content_type not in allowed_types:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidFileType',
                    'message': 'File must be PDF or Word document.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload to Cloudinary and store the secure_url directly
        from core.storage import upload_to_cloudinary
        try:
            result = upload_to_cloudinary(file, 'recommendations')
        except Exception as exc:
            logger.error("Cloudinary upload failed for recommendation (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {'code': 503, 'type': 'UploadFailed', 'message': 'File upload failed. Please try again.'}
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        secure_url = result.get('secure_url')
        if secure_url:
            type(kyc).objects.filter(pk=kyc.pk).update(recommendation_letter=secure_url)

        return Response({
            'success': True,
            'data': {
                'recommendation_letter': secure_url
            },
            'message': 'Recommendation letter uploaded successfully.'
        })


# =============================================================================
# EAGLET (MENTEE) PROFILE VIEWS
# =============================================================================

class EagletProfileView(APIView):
    """
    Get or update eaglet profile.

    GET /api/v1/auth/eaglet/profile/
    PATCH /api/v1/auth/eaglet/profile/
    """

    permission_classes = [IsAuthenticated, IsEaglet]

    def get(self, request):
        profile, created = EagletProfile.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': EagletProfileSerializer(profile).data
        })

    def patch(self, request):
        profile, _ = EagletProfile.objects.get_or_create(user=request.user)

        serializer = EagletOnboardingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(eaglet_profile=profile)

        return Response({
            'success': True,
            'data': EagletProfileSerializer(profile).data
        })


class EagletOnboardingView(APIView):
    """
    Complete eaglet onboarding.

    POST /api/v1/auth/eaglet/onboarding/
    """

    permission_classes = [IsAuthenticated, IsEaglet]

    def post(self, request):
        profile, _ = EagletProfile.objects.get_or_create(user=request.user)

        # Check if already completed
        if profile.onboarding_completed:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'AlreadyCompleted',
                    'message': 'Onboarding has already been completed. Use PATCH /eaglet/profile/ to update your profile.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = EagletCompleteOnboardingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(eaglet_profile=profile)

        # Send welcome email
        try:
            from .tasks import send_eaglet_welcome_email
            send_eaglet_welcome_email.delay(str(request.user.id))
        except Exception:
            pass

        return Response({
            'success': True,
            'data': EagletProfileSerializer(profile).data,
            'message': 'Welcome to Eagles & Eaglets! Your profile has been set up successfully.'
        })


class EagletSkipOnboardingView(APIView):
    """
    Skip eaglet onboarding for now.

    POST /api/v1/auth/eaglet/onboarding/skip/
    """

    permission_classes = [IsAuthenticated, IsEaglet]

    def post(self, request):
        profile, _ = EagletProfile.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': EagletProfileSerializer(profile).data,
            'message': 'Onboarding skipped. You can complete your profile anytime from settings.'
        })


# =============================================================================
# NEW PROFILE/KYC VIEWS (PM Requirements - Both roles need approval)
# =============================================================================

class MentorProfileView(APIView):
    """
    Get or update mentor profile/KYC (NEW PM requirements).

    GET /api/v1/auth/mentor-profile/
    PATCH /api/v1/auth/mentor-profile/
    """

    permission_classes = [IsAuthenticated, IsEagle]

    def get(self, request):
        kyc, created = MentorKYC.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': MentorKYCNewSerializer(kyc).data
        })

    def patch(self, request):
        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to approved applications
        if kyc.status == 'approved':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify an approved profile.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Allow editing for draft, rejected, and requires_changes status
        if kyc.status in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationPending',
                    'message': 'Your profile is currently under review. Please wait for admin feedback.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = MentorKYCNewUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(mentor_kyc=kyc, user=request.user)

        return Response({
            'success': True,
            'data': MentorKYCNewSerializer(kyc).data,
            'message': 'Profile updated successfully.'
        })


class MenteeProfileView(APIView):
    """
    Get or update mentee profile/KYC (NEW PM requirements).

    GET /api/v1/auth/mentee-profile/
    PATCH /api/v1/auth/mentee-profile/
    """

    permission_classes = [IsAuthenticated, IsEaglet]

    def get(self, request):
        kyc, created = MenteeKYC.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': MenteeKYCSerializer(kyc).data
        })

    def patch(self, request):
        kyc, _ = MenteeKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to approved applications
        if kyc.status == 'approved':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify an approved profile.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Allow editing for draft, rejected, and requires_changes status
        if kyc.status in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationPending',
                    'message': 'Your profile is currently under review. Please wait for admin feedback.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = MenteeKYCUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(mentee_kyc=kyc)

        return Response({
            'success': True,
            'data': MenteeKYCSerializer(kyc).data,
            'message': 'Profile updated successfully.'
        })


class ProfileSubmitView(APIView):
    """
    Submit profile/KYC for admin review (works for both Eagles and Eaglets).

    POST /api/v1/auth/profile/submit/
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if user.is_eagle:
            return self._submit_mentor_profile(request)
        elif user.is_eaglet:
            return self._submit_mentee_profile(request)
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidRole',
                    'message': 'Profile submission is only available for Eagles and Eaglets.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

    def _submit_mentor_profile(self, request):
        """Submit mentor KYC for review."""
        try:
            kyc = MentorKYC.objects.get(user=request.user)
        except MentorKYC.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'Profile not found. Please complete your profile first.'
                }
            }, status=status.HTTP_404_NOT_FOUND)

        # Check if already submitted
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'AlreadySubmitted',
                    'message': 'Your profile has already been submitted.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Try to submit using the model's submit method
        if kyc.submit():
            # Send confirmation email
            try:
                from .tasks import send_profile_submitted_email
                send_profile_submitted_email.delay(str(request.user.id), 'mentor')
            except Exception as e:
                logger.warning(f"Failed to send profile submitted email: {e}")

            return Response({
                'success': True,
                'data': MentorKYCNewSerializer(kyc).data,
                'message': 'Profile submitted successfully. Our team will review it within 2-3 business days.'
            })
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'IncompleteProfile',
                    'message': 'Please complete all required fields before submitting.',
                    'details': {
                        'completion_percentage': kyc.completion_percentage
                    }
                }
            }, status=status.HTTP_400_BAD_REQUEST)

    def _submit_mentee_profile(self, request):
        """Submit mentee KYC for review."""
        try:
            kyc = MenteeKYC.objects.get(user=request.user)
        except MenteeKYC.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'Profile not found. Please complete your profile first.'
                }
            }, status=status.HTTP_404_NOT_FOUND)

        # Check if already submitted
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'AlreadySubmitted',
                    'message': 'Your profile has already been submitted.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Try to submit using the model's submit method
        if kyc.submit():
            # Send confirmation email
            try:
                from .tasks import send_profile_submitted_email
                send_profile_submitted_email.delay(str(request.user.id), 'mentee')
            except Exception as e:
                logger.warning(f"Failed to send profile submitted email: {e}")

            return Response({
                'success': True,
                'data': MenteeKYCSerializer(kyc).data,
                'message': 'Profile submitted successfully. Our team will review it within 2-3 business days.'
            })
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'IncompleteProfile',
                    'message': 'Please complete all required fields before submitting.',
                    'details': {
                        'completion_percentage': kyc.completion_percentage
                    }
                }
            }, status=status.HTTP_400_BAD_REQUEST)


class UploadDisplayPictureView(APIView):
    """
    Upload profile/display picture (works for both Eagles and Eaglets).

    POST /api/v1/auth/upload/picture/
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        user = request.user

        # Get the appropriate KYC model
        if user.is_eagle:
            kyc, _ = MentorKYC.objects.get_or_create(user=user)
        elif user.is_eaglet:
            kyc, _ = MenteeKYC.objects.get_or_create(user=user)
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidRole',
                    'message': 'Picture upload is only available for Eagles and Eaglets.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if profile is locked
        if kyc.status == 'approved':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ProfileLocked',
                    'message': 'Cannot modify an approved profile.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        if kyc.status in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ProfilePending',
                    'message': 'Your profile is under review. Wait for admin feedback to make changes.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get uploaded file
        file = request.FILES.get('file') or request.FILES.get('display_picture')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded. Please select an image file.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate the file using our validator
        try:
            validate_image_file(file)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidFile',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload via Cloudinary with optimization
        from core.storage import upload_to_cloudinary, get_optimized_url
        try:
            result = upload_to_cloudinary(file, 'profile_pictures')
        except Exception as exc:
            logger.error("Cloudinary upload failed for display_picture (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {'code': 503, 'type': 'UploadFailed', 'message': 'File upload failed. Please try again.'}
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        secure_url = result.get('secure_url')
        public_id = result.get('public_id')

        # Store secure_url directly — display_picture is now a URLField
        if secure_url:
            type(kyc).objects.filter(pk=kyc.pk).update(display_picture=secure_url)

        return Response({
            'success': True,
            'data': {
                'display_picture': secure_url,
                'optimized_url': get_optimized_url(public_id, preset='profile') if public_id else None,
                'thumbnail_url': get_optimized_url(public_id, preset='thumbnail') if public_id else None,
            },
            'message': 'Profile picture uploaded successfully.'
        })


class UploadCVView(APIView):
    """
    Upload CV document (works for both Eagles and Eaglets).

    POST /api/v1/auth/upload/cv/
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        user = request.user

        # Get the appropriate KYC model
        if user.is_eagle:
            kyc, _ = MentorKYC.objects.get_or_create(user=user)
        elif user.is_eaglet:
            kyc, _ = MenteeKYC.objects.get_or_create(user=user)
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidRole',
                    'message': 'CV upload is only available for Eagles and Eaglets.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if profile is locked
        if kyc.status == 'approved':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ProfileLocked',
                    'message': 'Cannot modify an approved profile.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        if kyc.status in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ProfilePending',
                    'message': 'Your profile is under review. Wait for admin feedback to make changes.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get uploaded file
        file = request.FILES.get('file') or request.FILES.get('cv')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded. Please select a PDF or DOCX file.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate the file using our validator
        try:
            validate_cv_file(file)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidFile',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload to Cloudinary and store the secure_url directly
        from core.storage import upload_to_cloudinary
        try:
            result = upload_to_cloudinary(file, 'cvs')
        except Exception as exc:
            logger.error("Cloudinary upload failed for CV (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {'code': 503, 'type': 'UploadFailed', 'message': 'File upload failed. Please try again.'}
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        secure_url = result.get('secure_url')
        if secure_url:
            type(kyc).objects.filter(pk=kyc.pk).update(cv=secure_url)

        return Response({
            'success': True,
            'data': {
                'cv': secure_url
            },
            'message': 'CV uploaded successfully.'
        })


# =============================================================================
# GOOGLE OAUTH VIEWS
# =============================================================================

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

        return Response({
            'success': True,
            'data': response_data
        })


# =============================================================================
# ADMIN KYC MANAGEMENT VIEWS
# =============================================================================

class AdminKYCListView(APIView):
    """
    List all KYC applications for admin review (both mentors and mentees).

    GET /api/v1/admin/kyc/
    Query params:
        - role: Filter by role (mentor, mentee, all) - defaults to 'all'
        - status: Filter by status (submitted, under_review, approved, rejected, requires_changes)
        - priority: Filter by priority (high, medium, low)
        - search: Search by user name or email
        - ordering: Sort by field (submitted_at, -submitted_at, created_at, -created_at)
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        from django.db.models import Q, Count, Case, When

        role_filter = request.GET.get('role', 'all')
        status_filter = request.GET.get('status')
        search = request.GET.get('search')
        ordering = request.GET.get('ordering', '-submitted_at')
        page = int(request.GET.get('page', 1))
        per_page = min(int(request.GET.get('per_page', 20)), 100)

        # Build results based on role filter
        mentor_applications = []
        mentee_applications = []

        # Query mentors if needed
        if role_filter in ['mentor', 'all']:
            mentor_qs = MentorKYC.objects.select_related('user').all()

            if status_filter:
                if status_filter == 'pending':
                    mentor_qs = mentor_qs.filter(status__in=['submitted', 'under_review'])
                else:
                    mentor_qs = mentor_qs.filter(status=status_filter)

            if search:
                mentor_qs = mentor_qs.filter(
                    Q(user__email__icontains=search) |
                    Q(user__first_name__icontains=search) |
                    Q(user__last_name__icontains=search)
                )

            mentor_applications = list(mentor_qs)

        # Query mentees if needed
        if role_filter in ['mentee', 'all']:
            mentee_qs = MenteeKYC.objects.select_related('user').all()

            if status_filter:
                if status_filter == 'pending':
                    mentee_qs = mentee_qs.filter(status__in=['submitted', 'under_review'])
                else:
                    mentee_qs = mentee_qs.filter(status=status_filter)

            if search:
                mentee_qs = mentee_qs.filter(
                    Q(user__email__icontains=search) |
                    Q(user__first_name__icontains=search) |
                    Q(user__last_name__icontains=search)
                )

            mentee_applications = list(mentee_qs)

        # Serialize applications with role tag
        all_applications = []

        for kyc in mentor_applications:
            data = MentorKYCListSerializer(kyc).data
            data['role'] = 'mentor'
            data['role_display'] = 'Eagle (Mentor)'
            all_applications.append(data)

        for kyc in mentee_applications:
            data = MenteeKYCListSerializer(kyc).data
            data['role'] = 'mentee'
            data['role_display'] = 'Eaglet (Mentee)'
            all_applications.append(data)

        # Sort combined list
        reverse = ordering.startswith('-')
        sort_field = ordering.lstrip('-')
        if sort_field in ['submitted_at', 'created_at']:
            all_applications.sort(
                key=lambda x: x.get(sort_field) or '',
                reverse=reverse
            )

        # Pagination
        total = len(all_applications)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = all_applications[start:end]

        # Get summary counts using aggregate (2 queries instead of 14)
        def _get_status_counts(model):
            """Single-query aggregation for all status counts."""
            return model.objects.aggregate(
                total=Count('id'),
                pending=Count(Case(When(status__in=['submitted', 'under_review'], then=1))),
                approved=Count(Case(When(status='approved', then=1))),
                rejected=Count(Case(When(status='rejected', then=1))),
                requires_changes=Count(Case(When(status='requires_changes', then=1))),
            )

        mentor_counts = _get_status_counts(MentorKYC)
        mentee_counts = _get_status_counts(MenteeKYC)

        summary = {
            'total': mentor_counts['total'] + mentee_counts['total'],
            'pending': mentor_counts['pending'] + mentee_counts['pending'],
            'approved': mentor_counts['approved'] + mentee_counts['approved'],
            'rejected': mentor_counts['rejected'] + mentee_counts['rejected'],
            'requires_changes': mentor_counts['requires_changes'] + mentee_counts['requires_changes'],
            'mentors': {
                'total': mentor_counts['total'],
                'pending': mentor_counts['pending'],
            },
            'mentees': {
                'total': mentee_counts['total'],
                'pending': mentee_counts['pending'],
            },
        }

        return Response({
            'success': True,
            'data': {
                'applications': paginated,
                'summary': summary,
                'pagination': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (total + per_page - 1) // per_page,
                }
            }
        })


class AdminKYCDetailView(APIView):
    """
    Get detailed KYC application for admin review (supports both mentor and mentee).

    GET /api/v1/admin/kyc/{kyc_id}/
    Query params:
        - role: 'mentor' or 'mentee' (required to identify which model to query)

    Note: This endpoint is read-only. To transition a KYC application from
    'submitted' to 'under_review', use the POST /admin/kyc/{kyc_id}/start-review/
    endpoint instead. GET requests must not have write side-effects per HTTP
    semantics (RFC 7231 §4.2.1).
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request, kyc_id):
        role = request.GET.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user', 'reviewed_by').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            data = MenteeKYCDetailSerializer(kyc).data
            data['role'] = 'mentee'
            data['role_display'] = 'Eaglet (Mentee)'
        else:
            try:
                kyc = MentorKYC.objects.select_related('user', 'reviewed_by').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            data = MentorKYCDetailSerializer(kyc).data
            data['role'] = 'mentor'
            data['role_display'] = 'Eagle (Mentor)'

        return Response({
            'success': True,
            'data': data
        })


class AdminKYCStartReviewView(APIView):
    """
    Explicitly start reviewing a KYC application.

    Transitions a KYC application from 'submitted' to 'under_review' status.
    This is the proper POST-based replacement for the previous auto-transition
    that was incorrectly triggered on GET requests.

    POST /api/v1/admin/kyc/{kyc_id}/start-review/
    Body params:
        - role: 'mentor' or 'mentee' (required)
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                kyc = MentorKYC.objects.select_related('user').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

        # Only transition from 'submitted' status
        if kyc.status != 'submitted':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStatusTransition',
                    'message': (
                        f'Cannot start review: application status is '
                        f'"{kyc.get_status_display()}" (expected "Submitted").'
                    )
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        kyc.status = 'under_review'
        kyc.save(update_fields=['status'])

        logger.info(
            "KYC %s transitioned to under_review by admin %s",
            kyc_id, request.user.email,
        )

        return Response({
            'success': True,
            'data': {
                'id': str(kyc.id),
                'status': kyc.status,
                'status_display': kyc.get_status_display(),
                'message': 'Application is now under review.',
            }
        })


class AdminKYCApproveView(APIView):
    """
    Approve a KYC application (supports both mentor and mentee).

    POST /api/v1/admin/kyc/{kyc_id}/approve/
    Body params:
        - role: 'mentor' or 'mentee' (required)
        - review_notes: Optional notes
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            serializer_class = MenteeKYCDetailSerializer
            role_display = 'Eaglet (Mentee)'
            feature_access = 'mentee features'
        else:
            try:
                kyc = MentorKYC.objects.select_related('user').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            serializer_class = MentorKYCDetailSerializer
            role_display = 'Eagle (Mentor)'
            feature_access = 'mentor features'

        # Check if can be approved
        if kyc.status not in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStatus',
                    'message': f'Cannot approve application with status "{kyc.get_status_display()}".'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = KYCApprovalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Save review notes if provided
        review_notes = serializer.validated_data.get('review_notes', '')
        if review_notes:
            kyc.review_notes = review_notes

        # Approve the application
        kyc.approve(request.user)

        # Auto-create a Nest for mentors if they are approved
        if role == 'mentor':
            try:
                from apps.nests.services import NestService
                from apps.nests.models import Nest
                # Check if mentor already has a nest
                if not Nest.objects.filter(eagle=kyc.user).exists():
                    nest_name = f"{kyc.user.first_name}'s Nest" if kyc.user.first_name else f"Eagle {kyc.user.id}'s Nest"
                    industry_focus = kyc.current_occupation if getattr(kyc, 'current_occupation', None) else "General"
                    description = getattr(kyc, 'profile_description', "Welcome to my Nest! Let's grow together.")
                    if not description:
                        description = "Welcome to my Nest! Let's grow together."
                        
                    NestService.create_nest(kyc.user, {
                        "name": nest_name,
                        "description": description,
                        "industry_focus": industry_focus,
                        "privacy": "public",
                        "max_members": getattr(kyc, 'max_mentees', 10) or 10
                    })
                    logger.info(f"Auto-created Nest for newly approved mentor: {kyc.user.email}")
            except Exception as e:
                logger.error(f"Failed to auto-create Nest for mentor {kyc.user.email}: {e}")

        # Send approval notification email
        try:
            from .tasks import send_profile_approved_email
            send_profile_approved_email.delay(str(kyc.user.id), role)
        except Exception as e:
            logger.error(f"Failed to queue approval email: {e}")

        data = serializer_class(kyc).data
        data['role'] = role
        data['role_display'] = role_display

        return Response({
            'success': True,
            'data': data,
            'message': f'Application approved successfully. {kyc.user.full_name} can now access {feature_access}.'
        })


class AdminKYCRejectView(APIView):
    """
    Reject a KYC application (supports both mentor and mentee).

    POST /api/v1/admin/kyc/{kyc_id}/reject/
    Body params:
        - role: 'mentor' or 'mentee' (required)
        - rejection_reason: Reason for rejection (required)
        - review_notes: Optional internal notes
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            serializer_class = MenteeKYCDetailSerializer
        else:
            try:
                kyc = MentorKYC.objects.select_related('user').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            serializer_class = MentorKYCDetailSerializer

        # Check if can be rejected
        if kyc.status not in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStatus',
                    'message': f'Cannot reject application with status "{kyc.get_status_display()}".'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = KYCRejectionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        rejection_reason = serializer.validated_data['rejection_reason']
        review_notes = serializer.validated_data.get('review_notes', '')

        # Reject the application
        kyc.reject(request.user, rejection_reason)

        # Save internal review notes if provided
        if review_notes:
            kyc.review_notes = review_notes
            kyc.save(update_fields=['review_notes'])

        # Send rejection notification email
        try:
            from .tasks import send_profile_rejected_email
            send_profile_rejected_email.delay(str(kyc.user.id), role, rejection_reason)
        except Exception as e:
            logger.error(f"Failed to queue rejection email: {e}")

        data = serializer_class(kyc).data
        data['role'] = role

        return Response({
            'success': True,
            'data': data,
            'message': 'Application rejected. The applicant has been notified.'
        })


class AdminKYCRequestChangesView(APIView):
    """
    Request changes on a KYC application (supports both mentor and mentee).

    POST /api/v1/admin/kyc/{kyc_id}/request-changes/
    Body params:
        - role: 'mentor' or 'mentee' (required)
        - review_notes: Required notes describing changes needed
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            serializer_class = MenteeKYCDetailSerializer
        else:
            try:
                kyc = MentorKYC.objects.select_related('user').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            serializer_class = MentorKYCDetailSerializer

        # Check if changes can be requested
        if kyc.status not in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStatus',
                    'message': f'Cannot request changes for application with status "{kyc.get_status_display()}".'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = KYCRequestChangesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        review_notes = serializer.validated_data['review_notes']

        # Request changes
        kyc.request_changes(request.user, review_notes)

        # Send notification email
        try:
            from .tasks import send_profile_changes_requested_email
            send_profile_changes_requested_email.delay(str(kyc.user.id), role, review_notes)
        except Exception as e:
            logger.error(f"Failed to queue changes requested email: {e}")

        data = serializer_class(kyc).data
        data['role'] = role

        return Response({
            'success': True,
            'data': data,
            'message': 'Changes requested. The applicant has been notified.'
        })


class AdminKYCNotesView(APIView):
    """
    Add internal notes to a KYC application (supports both mentor and mentee).

    POST /api/v1/admin/kyc/{kyc_id}/notes/
    Body params:
        - role: 'mentor' or 'mentee' (required)
        - note: The note content (required)
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                kyc = MentorKYC.objects.get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

        serializer = AdminInternalNoteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        note = serializer.validated_data['note']
        timestamp = timezone.now().strftime('%Y-%m-%d %H:%M')
        author = request.user.full_name

        # Append note with timestamp and author
        new_note = f"[{timestamp}] {author}: {note}"

        if kyc.review_notes:
            kyc.review_notes = f"{kyc.review_notes}\n\n{new_note}"
        else:
            kyc.review_notes = new_note

        kyc.save(update_fields=['review_notes'])

        return Response({
            'success': True,
            'data': {
                'review_notes': kyc.review_notes,
                'role': role
            },
            'message': 'Note added successfully.'
        })


class AdminDashboardStatsView(APIView):
    """
    Get dashboard statistics for admin.

    GET /api/v1/admin/stats/
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        from django.db.models import Count
        from django.db.models.functions import TruncDate, TruncWeek
        from datetime import timedelta

        period = request.query_params.get('period', 'weekly')

        # User stats
        total_users = User.objects.filter(deleted_at__isnull=True).count()
        total_eagles = User.objects.filter(role='eagle', deleted_at__isnull=True).count()
        total_eaglets = User.objects.filter(role='eaglet', deleted_at__isnull=True).count()
        suspended_users = User.objects.filter(status='suspended', deleted_at__isnull=True).count()

        # Mentor KYC stats
        mentor_kyc_stats = MentorKYC.objects.aggregate(
            total=Count('id'),
            pending=Count('id', filter=models.Q(status__in=['submitted', 'under_review'])),
            approved=Count('id', filter=models.Q(status='approved')),
            rejected=Count('id', filter=models.Q(status='rejected')),
            requires_changes=Count('id', filter=models.Q(status='requires_changes')),
        )

        # Mentee KYC stats
        mentee_kyc_stats = MenteeKYC.objects.aggregate(
            total=Count('id'),
            pending=Count('id', filter=models.Q(status__in=['submitted', 'under_review'])),
            approved=Count('id', filter=models.Q(status='approved')),
            rejected=Count('id', filter=models.Q(status='rejected')),
            requires_changes=Count('id', filter=models.Q(status='requires_changes')),
        )

        # Combined pending KYC
        total_pending_kyc = (mentor_kyc_stats['pending'] or 0) + (mentee_kyc_stats['pending'] or 0)

        # Registration chart data based on period
        if period == 'monthly':
            # Last 30 days — aggregated by week (4 data points)
            month_ago = timezone.now() - timedelta(days=28)
            recent_registrations = list(
                User.objects.filter(
                    created_at__gte=month_ago,
                    deleted_at__isnull=True
                ).annotate(
                    week=TruncWeek('created_at')
                ).values('week').annotate(
                    count=Count('id')
                ).order_by('week')
            )
            # Convert week dates to ISO strings for JSON serialization
            for entry in recent_registrations:
                entry['date'] = entry.pop('week').isoformat()[:10]
        else:
            # Last 7 days — daily granularity
            week_ago = timezone.now() - timedelta(days=7)
            recent_registrations = list(
                User.objects.filter(
                    created_at__gte=week_ago,
                    deleted_at__isnull=True
                ).annotate(
                    date=TruncDate('created_at')
                ).values('date').annotate(
                    count=Count('id')
                ).order_by('date')
            )

        # Recent activity (last 10 events from various sources)
        recent_activity = []

        # Recent user registrations
        new_users = User.objects.filter(
            deleted_at__isnull=True
        ).order_by('-created_at')[:5]
        for u in new_users:
            recent_activity.append({
                'type': 'registration',
                'icon': 'person_add',
                'icon_bg': 'bg-emerald-100 text-emerald-600',
                'title': 'New user registered',
                'description': f'{u.full_name} joined as {u.get_role_display()}',
                'timestamp': u.created_at.isoformat(),
            })

        # Recent KYC submissions (mentors)
        recent_mentor_kyc = MentorKYC.objects.filter(
            submitted_at__isnull=False
        ).select_related('user').order_by('-submitted_at')[:3]
        for kyc in recent_mentor_kyc:
            recent_activity.append({
                'type': 'kyc_submission',
                'icon': 'verified_user',
                'icon_bg': 'bg-blue-100 text-blue-600',
                'title': 'KYC submitted',
                'description': f'{kyc.user.full_name} (Eagle) submitted KYC for review',
                'timestamp': kyc.submitted_at.isoformat(),
            })

        # Recent KYC submissions (mentees)
        recent_mentee_kyc = MenteeKYC.objects.filter(
            submitted_at__isnull=False
        ).select_related('user').order_by('-submitted_at')[:3]
        for kyc in recent_mentee_kyc:
            recent_activity.append({
                'type': 'kyc_submission',
                'icon': 'how_to_reg',
                'icon_bg': 'bg-purple-100 text-purple-600',
                'title': 'KYC submitted',
                'description': f'{kyc.user.full_name} (Eaglet) submitted KYC for review',
                'timestamp': kyc.submitted_at.isoformat(),
            })

        # Recent suspensions
        suspended = User.objects.filter(
            status='suspended',
            suspended_at__isnull=False
        ).order_by('-suspended_at')[:2]
        for u in suspended:
            recent_activity.append({
                'type': 'suspension',
                'icon': 'block',
                'icon_bg': 'bg-red-100 text-red-600',
                'title': 'User suspended',
                'description': f'{u.full_name} was suspended',
                'timestamp': u.suspended_at.isoformat(),
            })

        # Sort all activity by timestamp (most recent first)
        recent_activity.sort(key=lambda x: x['timestamp'], reverse=True)
        recent_activity = recent_activity[:10]

        return Response({
            'success': True,
            'data': {
                'users': {
                    'total': total_users,
                    'eagles': total_eagles,
                    'eaglets': total_eaglets,
                    'suspended': suspended_users,
                },
                'kyc': {
                    'mentor': mentor_kyc_stats,
                    'mentee': mentee_kyc_stats,
                    'total_pending': total_pending_kyc,
                },
                'recent_registrations': recent_registrations,
                'chart_period': period,
                'recent_activity': recent_activity,
            }
        })


class AdminUserListView(APIView):
    """
    List all platform users with filtering, search, and pagination.
    GET /api/v1/auth/admin/users/
    Query params:
        - role: eagle | eaglet | admin | all (default: all)
        - status: active | suspended | pending | inactive | all (default: all)
        - search: search by name or email
        - ordering: created_at | -created_at | full_name | -full_name (default: -created_at)
        - page: page number (default: 1)
        - per_page: items per page (default: 20, max: 100)
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        from django.db.models import Q, Count, Sum, Value
        from django.db.models.functions import Coalesce
        from .serializers import AdminUserSerializer

        role_filter = request.GET.get('role', 'all')
        status_filter = request.GET.get('status', 'all')
        search = request.GET.get('search', '').strip()
        ordering = request.GET.get('ordering', '-created_at')
        page = max(1, int(request.GET.get('page', 1)))
        per_page = min(max(1, int(request.GET.get('per_page', 20))), 100)

        qs = User.objects.all()

        # Annotate with activity metrics
        qs = qs.annotate(
            total_points=Coalesce(Sum('point_transactions__points'), Value(0)),
            nests_count=Count('owned_nests', distinct=True),
            eaglets_count=Count(
                'owned_nests__memberships',
                filter=Q(owned_nests__memberships__status='active'),
                distinct=True,
            ),
            content_created=Count('created_modules', distinct=True),
            content_completed=Count(
                'content_progress',
                filter=Q(content_progress__status='completed'),
                distinct=True,
            ),
            assignments_completed=Count(
                'assignment_submissions',
                filter=Q(assignment_submissions__status__in=['submitted', 'graded']),
                distinct=True,
            ),
        )

        if role_filter != 'all':
            qs = qs.filter(role=role_filter)

        if status_filter != 'all':
            qs = qs.filter(status=status_filter)

        if search:
            qs = qs.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )

        # Validate and apply ordering
        allowed_ordering = {'created_at', '-created_at', 'first_name', '-first_name', 'email', '-email', 'last_login', '-last_login'}
        if ordering not in allowed_ordering:
            ordering = '-created_at'
        qs = qs.order_by(ordering)

        total = qs.count()
        start = (page - 1) * per_page
        users = qs[start:start + per_page]

        serializer = AdminUserSerializer(users, many=True)

        return Response({
            'success': True,
            'data': {
                'users': serializer.data,
                'pagination': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': max(1, (total + per_page - 1) // per_page),
                }
            }
        })


class AdminSuspendUserView(APIView):
    """
    Suspend an approved user (revoke platform access).
    POST /api/v1/auth/admin/users/<user_id>/suspend/
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'User not found.',
                }
            }, status=status.HTTP_404_NOT_FOUND)

        # Can't suspend admins
        if user.role == 'admin':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ValidationError',
                    'message': 'Cannot suspend admin users.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Can't suspend already suspended users
        if user.status == 'suspended':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ValidationError',
                    'message': 'User is already suspended.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate reason
        reason = request.data.get('reason', '').strip()
        if not reason or len(reason) < 10:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ValidationError',
                    'message': 'A suspension reason of at least 10 characters is required.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        user.suspend(request.user, reason)

        return Response({
            'success': True,
            'data': {
                'message': f'{user.full_name} has been suspended.',
                'user_id': str(user.id),
                'status': user.status,
                'suspended_at': user.suspended_at.isoformat(),
            }
        })


class AdminReactivateUserView(APIView):
    """
    Reactivate a suspended user.
    POST /api/v1/auth/admin/users/<user_id>/reactivate/
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'User not found.',
                }
            }, status=status.HTTP_404_NOT_FOUND)

        if user.status != 'suspended':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ValidationError',
                    'message': 'User is not currently suspended.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        user.reactivate(request.user)

        return Response({
            'success': True,
            'data': {
                'message': f'{user.full_name} has been reactivated.',
                'user_id': str(user.id),
                'status': user.status,
            }
        })

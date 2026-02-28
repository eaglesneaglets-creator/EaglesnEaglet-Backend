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
from core.throttling import BurstRateThrottle, LoginRateThrottle

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

class RegisterView(APIView):
    """
    User registration endpoint.

    POST /api/v1/auth/register/
    """

    permission_classes = [AllowAny]
    throttle_classes = [BurstRateThrottle]

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
                return Response({
                    'success': True,
                    'data': response.data
                })
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
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()

            return Response({
                'success': True,
                'message': 'Successfully logged out.'
            }, status=status.HTTP_200_OK)
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
    Custom token refresh view with graceful error handling.

    POST /api/v1/auth/token/refresh/

    Handles cases where user no longer exists (e.g., after database flush)
    """

    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            return response
        except (TokenError, InvalidToken) as e:
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
            logger.error(f"Token refresh error: {str(e)}")
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
    throttle_classes = [BurstRateThrottle]

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
            try:
                kyc = MentorKYC.objects.get(user=user)
                data['kyc_status'] = kyc.status
                data['kyc_completion'] = kyc.completion_percentage
            except MentorKYC.DoesNotExist:
                data['kyc_status'] = None
                data['kyc_completion'] = 0

        # Include profile status for Eaglets
        if user.is_eaglet:
            try:
                profile = EagletProfile.objects.get(user=user)
                data['profile_completeness'] = profile.profile_completeness
                data['onboarding_completed'] = profile.onboarding_completed
            except EagletProfile.DoesNotExist:
                data['profile_completeness'] = 0
                data['onboarding_completed'] = False

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

        # Save the file
        kyc.government_id = file
        kyc.save(update_fields=['government_id'])

        return Response({
            'success': True,
            'data': {
                'government_id': kyc.government_id.url if kyc.government_id else None
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

        # Save the file
        kyc.recommendation_letter = file
        kyc.save(update_fields=['recommendation_letter'])

        return Response({
            'success': True,
            'data': {
                'recommendation_letter': kyc.recommendation_letter.url if kyc.recommendation_letter else None
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

        # Save the file
        kyc.display_picture = file
        kyc.save(update_fields=['display_picture'])

        return Response({
            'success': True,
            'data': {
                'display_picture': kyc.display_picture.url if kyc.display_picture else None
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

        # Save the file
        kyc.cv = file
        kyc.save(update_fields=['cv'])

        return Response({
            'success': True,
            'data': {
                'cv': kyc.cv.url if kyc.cv else None
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

    GET /api/v1/auth/google/login/
    """

    permission_classes = [AllowAny]

    def get(self, request):
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

        # Get role from query params (will be passed back via state)
        role = request.GET.get('role', 'eaglet')
        if role not in ['eagle', 'eaglet']:
            role = 'eaglet'

        # Build Google OAuth URL
        params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'email profile openid',
            'access_type': 'offline',
            'prompt': 'consent',
            'state': role,  # Pass role in state parameter
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

    def post(self, request):
        code = request.data.get('code')
        role = request.data.get('role', 'eaglet')

        if not code:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'MissingCode',
                    'message': 'Authorization code is required.'
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
                logger.error(f"Google token exchange failed: {token_response.text}")
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
            logger.error(f"Google OAuth request failed: {e}")
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
                logger.error(f"Google user info failed: {user_info_response.text}")
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
            logger.error(f"Google user info request failed: {e}")
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
        from django.db.models import Q

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

        # Get summary counts for both roles
        summary = {
            'total': MentorKYC.objects.count() + MenteeKYC.objects.count(),
            'pending': (
                MentorKYC.objects.filter(status__in=['submitted', 'under_review']).count() +
                MenteeKYC.objects.filter(status__in=['submitted', 'under_review']).count()
            ),
            'approved': (
                MentorKYC.objects.filter(status='approved').count() +
                MenteeKYC.objects.filter(status='approved').count()
            ),
            'rejected': (
                MentorKYC.objects.filter(status='rejected').count() +
                MenteeKYC.objects.filter(status='rejected').count()
            ),
            'requires_changes': (
                MentorKYC.objects.filter(status='requires_changes').count() +
                MenteeKYC.objects.filter(status='requires_changes').count()
            ),
            # Role-specific counts
            'mentors': {
                'total': MentorKYC.objects.count(),
                'pending': MentorKYC.objects.filter(status__in=['submitted', 'under_review']).count(),
            },
            'mentees': {
                'total': MenteeKYC.objects.count(),
                'pending': MenteeKYC.objects.filter(status__in=['submitted', 'under_review']).count(),
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

            # Mark as under review if just submitted
            if kyc.status == 'submitted':
                kyc.status = 'under_review'
                kyc.save(update_fields=['status'])

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

            # Mark as under review if just submitted
            if kyc.status == 'submitted':
                kyc.status = 'under_review'
                kyc.save(update_fields=['status'])

            data = MentorKYCDetailSerializer(kyc).data
            data['role'] = 'mentor'
            data['role_display'] = 'Eagle (Mentor)'

        return Response({
            'success': True,
            'data': data
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
        from django.db.models.functions import TruncDate
        from datetime import timedelta

        # User stats
        total_users = User.objects.filter(deleted_at__isnull=True).count()
        total_eagles = User.objects.filter(role='eagle', deleted_at__isnull=True).count()
        total_eaglets = User.objects.filter(role='eaglet', deleted_at__isnull=True).count()

        # KYC stats
        kyc_stats = MentorKYC.objects.aggregate(
            total=Count('id'),
            pending=Count('id', filter=models.Q(status__in=['submitted', 'under_review'])),
            approved=Count('id', filter=models.Q(status='approved')),
            rejected=Count('id', filter=models.Q(status='rejected')),
            requires_changes=Count('id', filter=models.Q(status='requires_changes')),
        )

        # Recent registrations (last 7 days)
        week_ago = timezone.now() - timedelta(days=7)
        recent_registrations = User.objects.filter(
            created_at__gte=week_ago,
            deleted_at__isnull=True
        ).annotate(
            date=TruncDate('created_at')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')

        # Recent KYC submissions (last 5)
        recent_kyc = MentorKYC.objects.filter(
            status__in=['submitted', 'under_review']
        ).select_related('user').order_by('-submitted_at')[:5]

        return Response({
            'success': True,
            'data': {
                'users': {
                    'total': total_users,
                    'eagles': total_eagles,
                    'eaglets': total_eaglets,
                },
                'kyc': kyc_stats,
                'recent_registrations': list(recent_registrations),
                'recent_kyc_submissions': MentorKYCListSerializer(recent_kyc, many=True).data,
            }
        })

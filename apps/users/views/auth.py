"""
Authentication Views — register, login, logout, refresh, verify, password, current user

Auto-extracted from monolithic views.py during Phase 11.5-04 split.
"""

import logging

from django.conf import settings
from rest_framework import serializers, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from core.throttling import BurstRateThrottle, LoginRateThrottle, RegisterRateThrottle, PasswordResetThrottle

logger = logging.getLogger(__name__)

from ..models import User, MentorKYC, EagletProfile
from ..serializers import (
    CustomTokenObtainPairSerializer,
    UserSerializer,
    UserRegistrationSerializer,
    PasswordChangeSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer,
    ResendVerificationSerializer,
)


# =============================================================================
# COOKIE HELPERS — JWT httpOnly cookie management
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
    # Leading-dot parent domain so cookies span www. + api. subdomains in prod.
    cookie_domain = getattr(settings, 'AUTH_COOKIE_DOMAIN', None)

    response.set_cookie(
        key='access_token',
        value=str(access_token),
        httponly=True,
        secure=is_secure,
        samesite=samesite,
        max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
        path='/',
        domain=cookie_domain,
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
            domain=cookie_domain,
        )


def _clear_auth_cookies(response) -> None:
    """Delete both JWT cookies on logout."""
    is_secure = not settings.DEBUG
    samesite = 'None' if is_secure else 'Lax'
    # Domain must match the value used at set time, or the browser won't delete it.
    cookie_domain = getattr(settings, 'AUTH_COOKIE_DOMAIN', None)
    response.delete_cookie('access_token', path='/', samesite=samesite, domain=cookie_domain)
    response.delete_cookie('refresh_token', path='/', samesite=samesite, domain=cookie_domain)



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

        # Try to send verification email
        try:
            from ..tasks import send_verification_email

            # Raw token stashed by the serializer's create() — must be passed to task so
            # the email link contains the raw token, not its SHA-256 hash.
            raw_token = getattr(user, '_raw_verification_token', None)

            # Try async first (Celery)
            try:
                send_verification_email.delay(str(user.id), raw_token)
                email_sent = True
            except Exception as celery_error:
                # Celery not available, try synchronous send
                logger.warning(f"Celery not available, trying sync email: {celery_error}")
                try:
                    send_verification_email(str(user.id), raw_token)
                    email_sent = True
                except Exception as sync_error:
                    # Already logged above; email_sent stays False so the
                    # response message tells the user to use resend.
                    logger.error(f"Sync email send failed: {sync_error}")
        except ImportError as e:
            logger.error(f"Could not import send_verification_email: {e}")

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
                        'access': access,
                        # SECURITY TRADE-OFF (temporary — until same-origin
                        # domain is available):
                        # Refresh token is also returned in JSON so the FE
                        # can stash it in localStorage and survive cross-
                        # origin deploys where the HttpOnly cookie below is
                        # treated as third-party and blocked. XSS can
                        # exfiltrate this token. Once FE + BE share a
                        # parent domain (eTLD+1), DROP this line and rely
                        # solely on the cookie. See audit P0 #1.
                        'refresh': refresh,
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

            # SECURITY TRADE-OFF (temporary — see login view note for why).
            # We return the rotated refresh in the JSON body so the
            # cross-origin FE can store the new value in localStorage and
            # use it on the next refresh. When the platform has a single
            # parent domain, drop the 'refresh' field and rely on the
            # HttpOnly cookie alone.
            api_response = Response({
                'success': True,
                'access': str(access),
                'refresh': str(rotated_refresh) if rotated_refresh else None,
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
            # DB stores SHA-256 hash of the token (not the raw value), so we
            # must hash the incoming token before querying. The link in the
            # email contains the raw token; only the hash sits at rest.
            user = User.objects.get(
                email_verification_token=User._hash_token(token),
            )
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

            # Generate new token; capture raw value to pass to the Celery task.
            raw_token = user.generate_email_verification_token()

            # Send verification email asynchronously
            try:
                from ..tasks import send_verification_email
                send_verification_email.delay(str(user.id), raw_token)
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
            raw_token = user.generate_password_reset_token()

            # Send password reset email asynchronously
            try:
                from ..tasks import send_password_reset_email
                send_password_reset_email.delay(str(user.id), raw_token)
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
            # DB stores SHA-256 hash of the token (not the raw value), so we
            # must hash the incoming token before querying.
            user = User.objects.get(
                password_reset_token=User._hash_token(token),
            )
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

            # Mentor-application status (plan 16-01): lets the FE render the
            # "Apply to mentor" CTA + current application state without extra calls.
            from ..models_mentor_app import MentorApplication
            from ..services import mentor_application as mentor_app_svc

            latest_app = (
                MentorApplication.objects
                .filter(user=user)
                .order_by('-created_at')
                .first()
            )
            data['mentor_application_eligible'] = mentor_app_svc.is_eligible(user)
            data['mentor_application_status'] = latest_app.status if latest_app else None

            # Program access status (plan 14-02): everything FE needs to render
            # lock states without extra requests.
            from apps.nests.services import EnrollmentService
            data['access_status'] = EnrollmentService.access_status_for(user)

        # Admin role state (plan 18-01) — drives Settings → Account section
        # AND the first-promotion "land in admin mode" reveal in the
        # role-switcher. Shown for everyone (mentee, mentor, admin) so the
        # FE never has to special-case missing keys.
        from apps.users.models_admin import AdminRoleRequest
        from apps.users.services.admin_role import first_admin_session_key
        from django.core.cache import cache

        admin_block = {
            'eligible': False,
            'ineligible_reasons': [],
            'pending_request_id': None,
            'first_admin_session': False,
        }

        if user.is_eagle:
            elig = user.can_request_admin()
            admin_block['eligible'] = elig['eligible']
            admin_block['ineligible_reasons'] = elig['reasons']

            pending = (
                AdminRoleRequest.objects
                .filter(user=user, status=AdminRoleRequest.Status.PENDING)
                .only('id')
                .first()
            )
            if pending:
                admin_block['pending_request_id'] = str(pending.id)

        # Pop the one-shot flag so subsequent /auth/me/ calls return False
        # — FE only gets the reveal moment once per promotion.
        cache_key = first_admin_session_key(user.id)
        if cache.get(cache_key):
            admin_block['first_admin_session'] = True
            cache.delete(cache_key)

        data['admin_request'] = admin_block

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

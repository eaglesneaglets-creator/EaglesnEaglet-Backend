"""
Cookie-based JWT Authentication

Reads the JWT access token from an httpOnly cookie named 'access_token'.
Falls back to the standard Authorization: Bearer <token> header so that
API clients (mobile apps, Postman, curl) continue to work unchanged.

Used as the primary DEFAULT_AUTHENTICATION_CLASS in settings/base.py.
"""

from django.middleware.csrf import CsrfViewMiddleware
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.authentication import JWTAuthentication


class AccountSuspended(PermissionDenied):
    """403 raised when a suspended account presents a still-valid token.

    Deliberately a PermissionDenied (403), NOT AuthenticationFailed (401):
    the frontend treats 401 as "token expired" and auto-refreshes, which for a
    suspended user succeeds (the refresh token is still valid) and then fails
    again — an infinite refresh loop that dumps the user at the login screen
    with no explanation. A 403 with a stable ``code`` lets the client route
    straight to the /suspended page instead.
    """

    default_detail = "Your account has been suspended."
    default_code = "account_suspended"


class CsrfFailed(PermissionDenied):
    default_detail = "CSRF validation failed."
    default_code = "csrf_failed"


def enforce_csrf(request) -> None:
    """Apply Django's CSRF validation to cookie-authenticated API requests."""
    check = CsrfViewMiddleware(lambda _request: None)
    check.process_request(request)
    reason = check.process_view(request, None, (), {})
    if reason:
        raise CsrfFailed(f"CSRF validation failed: {reason}")


class CookieJWTAuthentication(JWTAuthentication):
    """
    Authenticate via httpOnly 'access_token' cookie.
    Falls back to Authorization: Bearer header for non-browser clients.

    Priority:
      1. access_token cookie (browser sessions — XSS-safe)
      2. Authorization: Bearer header (API clients / mobile apps)
    """

    #: Paths a suspended account may still reach. Logout's entire job is to
    #: DESTROY credentials, so gating it on account health traps the user: the
    #: auth cookies are httpOnly, meaning only a server response can delete them,
    #: and the server refuses to answer. The result is a browser that keeps
    #: sending valid suspended-user cookies forever — which also breaks a
    #: *different* person signing in on that browser. Suspended users keep
    #: exactly one capability: leaving.
    SUSPENDED_ALLOWED_PATHS = ("/api/v1/auth/logout/",)

    #: Set during authenticate() so the header path (where SimpleJWT calls
    #: get_user() without a request) can still check the exemption.
    _current_request = None

    def _suspension_exempt(self, request) -> bool:
        path = getattr(request, "path", "") or ""
        return path in self.SUSPENDED_ALLOWED_PATHS

    def get_user(self, validated_token, request=None):
        """Resolve the token's user, rejecting suspended accounts (Phase 26-01).

        Enforcing suspension HERE (not only via the IsNotSuspended permission)
        is deliberate: DRF's per-view ``permission_classes`` fully REPLACE the
        default permissions, so ~87 views that set ``[IsAuthenticated]`` would
        otherwise bypass a permission-layer suspension check. The auth layer
        runs on every request regardless of per-view permissions, so a suspended
        user's still-valid access token stops working immediately — no waiting
        for the 15-min token to expire. Mirrors how SimpleJWT rejects inactive
        users via USER_AUTHENTICATION_RULE.

        Exception: logout (see SUSPENDED_ALLOWED_PATHS).
        """
        user = super().get_user(validated_token)
        if getattr(user, "status", None) == "suspended":
            # `request` is passed explicitly on the cookie path; on the header
            # path SimpleJWT calls this with the token only, so fall back to the
            # request stashed in authenticate().
            effective_request = request or getattr(self, "_current_request", None)
            if effective_request is not None and self._suspension_exempt(effective_request):
                return user
            raise AccountSuspended()
        return user

    def authenticate(self, request):
        # 1. Try httpOnly cookie first
        raw_token = request.COOKIES.get('access_token')

        if raw_token is not None:
            try:
                validated_token = self.get_validated_token(raw_token)
                user = self.get_user(validated_token, request=request)
                enforce_csrf(request)
                return user, validated_token
            except (AccountSuspended, CsrfFailed):
                # A valid cookie with an account/CSRF denial is definitive,
                # not a reason to fall through to bearer authentication.
                raise
            except Exception:
                # Invalid or expired cookie — fall through to header
                pass

        # 2. Fall back to Authorization: Bearer <token> header.
        # SimpleJWT's authenticate() calls self.get_user(validated_token) with no
        # request, so stash it for the exemption check above.
        self._current_request = request
        try:
            return super().authenticate(request)
        finally:
            self._current_request = None

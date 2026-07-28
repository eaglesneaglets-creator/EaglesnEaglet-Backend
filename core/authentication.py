"""
Cookie-based JWT Authentication

Reads the JWT access token from an httpOnly cookie named 'access_token'.
Falls back to the standard Authorization: Bearer <token> header so that
API clients (mobile apps, Postman, curl) continue to work unchanged.

Used as the primary DEFAULT_AUTHENTICATION_CLASS in settings/base.py.
"""

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed


class CookieJWTAuthentication(JWTAuthentication):
    """
    Authenticate via httpOnly 'access_token' cookie.
    Falls back to Authorization: Bearer header for non-browser clients.

    Priority:
      1. access_token cookie (browser sessions — XSS-safe)
      2. Authorization: Bearer header (API clients / mobile apps)
    """

    def get_user(self, validated_token):
        """Resolve the token's user, rejecting suspended accounts (Phase 26-01).

        Enforcing suspension HERE (not only via the IsNotSuspended permission)
        is deliberate: DRF's per-view ``permission_classes`` fully REPLACE the
        default permissions, so ~87 views that set ``[IsAuthenticated]`` would
        otherwise bypass a permission-layer suspension check. The auth layer
        runs on every request regardless of per-view permissions, so a suspended
        user's still-valid access token stops working immediately — no waiting
        for the 15-min token to expire. Mirrors how SimpleJWT rejects inactive
        users via USER_AUTHENTICATION_RULE.
        """
        user = super().get_user(validated_token)
        if getattr(user, "status", None) == "suspended":
            raise AuthenticationFailed("Account is suspended.", code="user_suspended")
        return user

    def authenticate(self, request):
        # 1. Try httpOnly cookie first
        raw_token = request.COOKIES.get('access_token')

        if raw_token is not None:
            try:
                validated_token = self.get_validated_token(raw_token)
                return self.get_user(validated_token), validated_token
            except AuthenticationFailed:
                # Valid token but the user is rejected (e.g. suspended) — a
                # definitive denial, NOT a reason to fall through to the header.
                raise
            except Exception:
                # Invalid or expired cookie — fall through to header
                pass

        # 2. Fall back to Authorization: Bearer <token> header
        return super().authenticate(request)

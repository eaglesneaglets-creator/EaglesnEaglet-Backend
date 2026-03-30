"""
Cookie-based JWT Authentication

Reads the JWT access token from an httpOnly cookie named 'access_token'.
Falls back to the standard Authorization: Bearer <token> header so that
API clients (mobile apps, Postman, curl) continue to work unchanged.

Used as the primary DEFAULT_AUTHENTICATION_CLASS in settings/base.py.
"""

from rest_framework_simplejwt.authentication import JWTAuthentication


class CookieJWTAuthentication(JWTAuthentication):
    """
    Authenticate via httpOnly 'access_token' cookie.
    Falls back to Authorization: Bearer header for non-browser clients.

    Priority:
      1. access_token cookie (browser sessions — XSS-safe)
      2. Authorization: Bearer header (API clients / mobile apps)
    """

    def authenticate(self, request):
        # 1. Try httpOnly cookie first
        raw_token = request.COOKIES.get('access_token')

        if raw_token is not None:
            try:
                validated_token = self.get_validated_token(raw_token)
                return self.get_user(validated_token), validated_token
            except Exception:
                # Invalid or expired cookie — fall through to header
                pass

        # 2. Fall back to Authorization: Bearer <token> header
        return super().authenticate(request)

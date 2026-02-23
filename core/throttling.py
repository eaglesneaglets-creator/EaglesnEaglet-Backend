"""
Custom Throttling Classes

Rate limiting for API endpoints.
"""

from rest_framework.throttling import SimpleRateThrottle


class BurstRateThrottle(SimpleRateThrottle):
    """
    Limits burst requests within a short time window.
    Prevents rapid-fire requests.
    """

    scope = 'burst'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)

        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class LoginRateThrottle(SimpleRateThrottle):
    """
    Stricter throttling for login attempts.
    Prevents brute force attacks.
    """

    scope = 'login'

    def get_cache_key(self, request, view):
        # Throttle by IP for login attempts
        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }


class RegisterRateThrottle(SimpleRateThrottle):
    """
    Throttling for registration to prevent spam accounts.
    """

    scope = 'register'

    def get_cache_key(self, request, view):
        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }


class PasswordResetThrottle(SimpleRateThrottle):
    """
    Throttling for password reset requests.
    Prevents email bombing.
    """

    scope = 'password_reset'
    rate = '3/hour'

    def get_cache_key(self, request, view):
        # Throttle by email if provided, else by IP
        email = request.data.get('email', '')
        if email:
            return self.cache_format % {
                'scope': self.scope,
                'ident': email.lower()
            }
        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }


class FileUploadThrottle(SimpleRateThrottle):
    """
    Throttling for file uploads to prevent abuse.
    """

    scope = 'file_upload'
    rate = '20/hour'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return self.cache_format % {
                'scope': self.scope,
                'ident': request.user.pk
            }
        return None  # Only throttle authenticated users

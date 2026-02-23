"""
Security Middleware

Adds security headers and performs security checks on all requests.
"""

import logging
from django.conf import settings
from django.http import HttpResponseForbidden
import re

logger = logging.getLogger('django.security')


class SecurityHeadersMiddleware:
    """
    Adds comprehensive security headers to all responses.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Content Security Policy
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        response['Content-Security-Policy'] = '; '.join(csp_directives)

        # Permissions Policy (replaces Feature-Policy)
        response['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=(), '
            'payment=(), usb=(), magnetometer=(), gyroscope=()'
        )

        # Additional security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Remove server header
        if 'Server' in response:
            del response['Server']

        return response


class RateLimitByIPMiddleware:
    """
    Additional IP-based rate limiting for sensitive endpoints.
    Uses Redis for distributed rate limiting.
    """

    # Endpoints with stricter rate limits
    SENSITIVE_ENDPOINTS = [
        r'^/api/v\d+/auth/login',
        r'^/api/v\d+/auth/register',
        r'^/api/v\d+/auth/password-reset',
        r'^/api/v\d+/auth/verify',
    ]

    def __init__(self, get_response):
        self.get_response = get_response
        self.compiled_patterns = [re.compile(p) for p in self.SENSITIVE_ENDPOINTS]

    def __call__(self, request):
        from django.core.cache import cache

        # Check if this is a sensitive endpoint
        path = request.path
        is_sensitive = any(p.match(path) for p in self.compiled_patterns)

        if is_sensitive:
            ip = self.get_client_ip(request)
            cache_key = f'rate_limit:{ip}:{path}'

            # Get current request count
            request_count = cache.get(cache_key, 0)

            # Limit: 10 requests per minute for sensitive endpoints
            if request_count >= 10:
                logger.warning(
                    f'Rate limit exceeded for IP {ip} on {path}',
                    extra={'ip': ip, 'path': path, 'count': request_count}
                )
                return HttpResponseForbidden(
                    '{"error": {"code": 429, "message": "Too many requests. Please try again later."}}',
                    content_type='application/json'
                )

            # Increment counter with 60 second expiry
            cache.set(cache_key, request_count + 1, 60)

        return self.get_response(request)

    def get_client_ip(self, request):
        """Get the real client IP, considering proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SQLInjectionProtectionMiddleware:
    """
    Additional layer of SQL injection protection.
    Logs and blocks suspicious query patterns.
    """

    SUSPICIOUS_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION(\s+)SELECT",
        r"INSERT(\s+)INTO",
        r"DELETE(\s+)FROM",
        r"DROP(\s+)TABLE",
        r"UPDATE(\s+)\w+(\s+)SET",
    ]

    def __init__(self, get_response):
        self.get_response = get_response
        self.compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_PATTERNS
        ]

    def __call__(self, request):
        # Check query parameters
        query_string = request.META.get('QUERY_STRING', '')

        for pattern in self.compiled_patterns:
            if pattern.search(query_string):
                logger.warning(
                    f'Potential SQL injection attempt detected',
                    extra={
                        'ip': self.get_client_ip(request),
                        'path': request.path,
                        'query': query_string[:500],
                    }
                )
                return HttpResponseForbidden(
                    '{"error": {"code": 403, "message": "Invalid request"}}',
                    content_type='application/json'
                )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')

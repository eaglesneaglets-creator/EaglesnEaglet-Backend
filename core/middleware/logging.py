"""
Request Logging Middleware

Logs all incoming requests with structured data for monitoring and debugging.
"""

import logging
import time
import uuid
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('apps')


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Logs request/response details for monitoring and debugging.
    Adds request ID for tracing.
    """

    def process_request(self, request):
        # Generate unique request ID
        request.request_id = str(uuid.uuid4())
        request.start_time = time.time()

        # Add request ID to response headers
        request.META['HTTP_X_REQUEST_ID'] = request.request_id

    def process_response(self, request, response):
        # Calculate request duration
        duration = None
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time

        # Skip logging for health checks and static files
        path = request.path
        if path.startswith('/health') or path.startswith('/static'):
            return response

        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')

        # Log request details
        log_data = {
            'request_id': getattr(request, 'request_id', 'unknown'),
            'method': request.method,
            'path': path,
            'status_code': response.status_code,
            'duration_ms': round(duration * 1000, 2) if duration else None,
            'ip': ip,
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
            'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
        }

        # Log level based on status code
        if response.status_code >= 500:
            logger.error('Request failed', extra=log_data)
        elif response.status_code >= 400:
            logger.warning('Request error', extra=log_data)
        else:
            logger.info('Request completed', extra=log_data)

        # Add request ID to response headers for client-side tracing
        response['X-Request-ID'] = getattr(request, 'request_id', 'unknown')

        return response

    def process_exception(self, request, exception):
        """Log unhandled exceptions."""
        logger.exception(
            f'Unhandled exception: {str(exception)}',
            extra={
                'request_id': getattr(request, 'request_id', 'unknown'),
                'path': request.path,
                'method': request.method,
            }
        )
        return None

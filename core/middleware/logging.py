"""
Request Logging Middleware

Logs all incoming requests with structured data for monitoring and debugging.
"""

import logging
import time
import uuid
from django.utils.deprecation import MiddlewareMixin

from core.middleware.request_noise import resolve_request_log_level
from core.middleware.security import get_client_ip

logger = logging.getLogger('apps')


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Logs request/response details for monitoring and debugging.
    Adds request ID for tracing.

    Scanner traffic (/.env, wp-config probes, etc.) is not logged at WARNING
    to avoid flooding Railway's log ingestion quota.
    """

    def process_request(self, request):
        request.request_id = str(uuid.uuid4())
        request.start_time = time.time()
        request.META['HTTP_X_REQUEST_ID'] = request.request_id

    def process_response(self, request, response):
        duration = None
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time

        path = request.path
        if path.startswith('/health') or path.startswith('/static'):
            return response

        log_level = resolve_request_log_level(path, response.status_code)
        if log_level is None:
            response['X-Request-ID'] = getattr(request, 'request_id', 'unknown')
            return response

        log_data = {
            'request_id': getattr(request, 'request_id', 'unknown'),
            'method': request.method,
            'path': path,
            'status_code': response.status_code,
            'duration_ms': round(duration * 1000, 2) if duration else None,
            'ip': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
            'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
        }

        if log_level == 'ERROR':
            logger.error('Request failed', extra=log_data)
        elif log_level == 'WARNING':
            logger.warning('Request error', extra=log_data)
        else:
            message = 'Request not found' if response.status_code == 404 else 'Request completed'
            logger.info(message, extra=log_data)

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

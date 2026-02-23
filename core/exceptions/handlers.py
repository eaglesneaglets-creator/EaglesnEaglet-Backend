"""
Custom Exception Handlers

Standardized error response format for the API with comprehensive error handling.
"""

import logging
from django.core.exceptions import PermissionDenied, ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger('apps')


def custom_exception_handler(exc, context):
    """
    Custom exception handler that returns errors in a standardized format:
    {
        "success": false,
        "error": {
            "code": 400,
            "type": "ValidationError",
            "message": "...",
            "details": {...}
        }
    }
    """
    # Convert Django exceptions to DRF exceptions
    if isinstance(exc, Http404):
        exc = ResourceNotFoundException()
    elif isinstance(exc, PermissionDenied):
        exc = ForbiddenException()
    elif isinstance(exc, DjangoValidationError):
        exc = ValidationError(detail=exc.messages)

    # Get the standard DRF response
    response = exception_handler(exc, context)

    if response is not None:
        # Extract error details
        error_details = None
        error_message = 'An error occurred'

        if isinstance(response.data, dict):
            # Handle nested error structures
            if 'detail' in response.data:
                error_message = str(response.data['detail'])
            elif 'non_field_errors' in response.data:
                error_message = str(response.data['non_field_errors'][0])
                error_details = response.data
            else:
                error_message = 'Validation failed'
                error_details = response.data
        elif isinstance(response.data, list):
            error_message = str(response.data[0]) if response.data else 'An error occurred'
        else:
            error_message = str(response.data)

        error_response = {
            'success': False,
            'error': {
                'code': response.status_code,
                'type': exc.__class__.__name__,
                'message': error_message,
                'details': error_details,
            },
        }

        # Add request ID if available
        request = context.get('request')
        if request and hasattr(request, 'request_id'):
            error_response['error']['request_id'] = request.request_id

        response.data = error_response

        # Log the error
        if response.status_code >= 500:
            logger.error(
                f'Server error: {error_message}',
                extra={
                    'status_code': response.status_code,
                    'error_type': exc.__class__.__name__,
                    'path': request.path if request else None,
                },
                exc_info=True
            )
        elif response.status_code >= 400:
            logger.warning(
                f'Client error: {error_message}',
                extra={
                    'status_code': response.status_code,
                    'error_type': exc.__class__.__name__,
                    'path': request.path if request else None,
                }
            )

    return response


# =============================================================================
# Custom Exceptions
# =============================================================================

class BusinessLogicException(APIException):
    """Custom exception for business logic errors."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'A business logic error occurred.'
    default_code = 'business_logic_error'


class ResourceNotFoundException(APIException):
    """Custom exception for resource not found errors."""
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'The requested resource was not found.'
    default_code = 'resource_not_found'


class ForbiddenException(APIException):
    """Custom exception for forbidden access."""
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = 'You do not have permission to perform this action.'
    default_code = 'forbidden'


class InsufficientPointsException(APIException):
    """Custom exception when user doesn't have enough points."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Insufficient points for this action.'
    default_code = 'insufficient_points'


class PaymentFailedException(APIException):
    """Custom exception for payment failures."""
    status_code = status.HTTP_402_PAYMENT_REQUIRED
    default_detail = 'Payment processing failed.'
    default_code = 'payment_failed'


class RateLimitExceededException(APIException):
    """Custom exception for rate limit exceeded."""
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = 'Rate limit exceeded. Please try again later.'
    default_code = 'rate_limit_exceeded'


class InvalidTokenException(APIException):
    """Custom exception for invalid tokens."""
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Invalid or expired token.'
    default_code = 'invalid_token'


class AccountDisabledException(APIException):
    """Custom exception for disabled accounts."""
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = 'This account has been disabled.'
    default_code = 'account_disabled'


class EmailNotVerifiedException(APIException):
    """Custom exception for unverified email."""
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = 'Please verify your email address to continue.'
    default_code = 'email_not_verified'


class DuplicateResourceException(APIException):
    """Custom exception for duplicate resource creation."""
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'This resource already exists.'
    default_code = 'duplicate_resource'


class FileUploadException(APIException):
    """Custom exception for file upload errors."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'File upload failed.'
    default_code = 'file_upload_error'


class ServiceUnavailableException(APIException):
    """Custom exception for service unavailability."""
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'Service temporarily unavailable. Please try again later.'
    default_code = 'service_unavailable'

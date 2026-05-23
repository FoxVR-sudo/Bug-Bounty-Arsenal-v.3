"""
Error handling middleware and utilities
"""
import logging
import traceback
from django.http import JsonResponse
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework import status

logger = logging.getLogger(__name__)


class ErrorHandlingMiddleware:
    """
    Global error handling middleware
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_exception(self, request, exception):
        """
        Handle uncaught exceptions globally
        """

        # Log the exception
        logger.error(
            f"Unhandled exception in {request.path}",
            exc_info=True,
            extra={
                'user': getattr(request, 'user', None),
                'method': request.method,
                'path': request.path,
                'ip': get_client_ip(request),
            }
        )

        # Different responses for different exception types
        if isinstance(exception, PermissionDenied):
            return JsonResponse({
                'error': 'Permission denied',
                'detail': str(exception)
            }, status=status.HTTP_403_FORBIDDEN)

        elif isinstance(exception, ValidationError):
            return JsonResponse({
                'error': 'Validation error',
                'detail': exception.message_dict if hasattr(exception, 'message_dict') else str(exception)
            }, status=status.HTTP_400_BAD_REQUEST)

        elif isinstance(exception, DatabaseError):
            return JsonResponse({
                'error': 'Database error',
                'detail': 'A database error occurred. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        else:
            # Generic server error
            return JsonResponse({
                'error': 'Internal server error',
                'detail': 'An unexpected error occurred. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def custom_exception_handler(exc, context):
    """
    Custom DRF exception handler with enhanced logging
    """

    # Call DRF's default exception handler first
    response = drf_exception_handler(exc, context)

    # Log the exception
    if response is None:
        # Unhandled exception
        logger.error(
            f"Unhandled DRF exception: {exc}",
            exc_info=True,
            extra={
                'view': context.get('view'),
                'request': context.get('request'),
            }
        )
    else:
        # Handled exception
        logger.warning(
            f"DRF exception: {exc}",
            extra={
                'status_code': response.status_code,
                'view': context.get('view'),
                'request': context.get('request'),
            }
        )

    # Add custom error tracking ID
    if response is not None:
        import uuid
        error_id = str(uuid.uuid4())
        response.data['error_id'] = error_id

        logger.info(f"Error ID: {error_id}")

    return response


def get_client_ip(request):
    """
    Get client IP address from request

    Args:
        request: Django request object

    Returns:
        str: Client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class ScanErrorHandler:
    """
    Error handler specific to scan operations
    """

    @staticmethod
    def handle_detector_error(scan_id, detector_name, exception):
        """
        Handle errors during detector execution

        Args:
            scan_id: Scan ID
            detector_name: Name of the detector
            exception: Exception that occurred

        Returns:
            dict: Error details
        """
        error_details = {
            'detector': detector_name,
            'error_type': type(exception).__name__,
            'error_message': str(exception),
            'traceback': traceback.format_exc()
        }

        logger.error(
            f"Detector error in scan #{scan_id}",
            extra=error_details
        )

        return error_details

    @staticmethod
    def handle_timeout_error(scan_id, detector_name, timeout_seconds):
        """
        Handle detector timeout

        Args:
            scan_id: Scan ID
            detector_name: Name of the detector
            timeout_seconds: Timeout duration

        Returns:
            dict: Timeout details
        """
        timeout_details = {
            'detector': detector_name,
            'timeout': timeout_seconds,
            'reason': 'Detector execution exceeded timeout limit'
        }

        logger.warning(
            f"Detector timeout in scan #{scan_id}",
            extra=timeout_details
        )

        return timeout_details


class ValidationHelper:
    """
    Common validation utilities
    """

    @staticmethod
    def validate_url(url):
        """
        Validate URL format and security

        Args:
            url (str): URL to validate

        Returns:
            tuple: (is_valid, error_message)
        """
        from urllib.parse import urlparse

        if not url:
            return False, "URL is required"

        try:
            parsed = urlparse(url)

            if not parsed.scheme:
                return False, "URL must include scheme (http:// or https://)"

            if parsed.scheme not in ['http', 'https']:
                return False, "Only HTTP and HTTPS protocols are supported"

            if not parsed.netloc:
                return False, "Invalid URL format"

            # Prevent localhost/internal IPs in production
            blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
            if parsed.netloc.split(':')[0] in blocked_hosts:
                return False, "Cannot scan localhost or internal addresses"

            return True, None

        except Exception as e:
            return False, f"Invalid URL: {str(e)}"

    @staticmethod
    def sanitize_input(text, max_length=1000):
        """
        Sanitize user input

        Args:
            text (str): Input text
            max_length (int): Maximum allowed length

        Returns:
            str: Sanitized text
        """
        if not text:
            return ""

        # Remove null bytes
        text = text.replace('\x00', '')

        # Limit length
        if len(text) > max_length:
            text = text[:max_length]

        # Strip whitespace
        text = text.strip()

        return text

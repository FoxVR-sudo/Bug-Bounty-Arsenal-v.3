"""
Unit tests for Error Handling utilities
"""
from django.test import RequestFactory
from django.http import JsonResponse
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError
from utils.error_handling import (
    ErrorHandlingMiddleware,
    get_client_ip,
    ScanErrorHandler,
    ValidationHelper
)


class TestErrorHandlingMiddleware:
    """Test ErrorHandlingMiddleware"""

    def test_middleware_init(self):
        """Test middleware initialization"""
        def dummy_get_response(request):
            return JsonResponse({'status': 'ok'})

        middleware = ErrorHandlingMiddleware(dummy_get_response)
        assert middleware.get_response == dummy_get_response

    def test_middleware_call_success(self):
        """Test middleware passes through successful responses"""
        def dummy_get_response(request):
            return JsonResponse({'status': 'ok'})

        middleware = ErrorHandlingMiddleware(dummy_get_response)
        factory = RequestFactory()
        request = factory.get('/test/')

        response = middleware(request)
        assert response.status_code == 200

    def test_process_exception_permission_denied(self):
        """Test handling of PermissionDenied exception"""
        def dummy_get_response(request):
            return JsonResponse({'status': 'ok'})

        middleware = ErrorHandlingMiddleware(dummy_get_response)
        factory = RequestFactory()
        request = factory.get('/test/')

        exception = PermissionDenied("Access denied")
        response = middleware.process_exception(request, exception)

        assert response.status_code == 403
        assert b'Permission denied' in response.content

    def test_process_exception_validation_error(self):
        """Test handling of ValidationError"""
        def dummy_get_response(request):
            return JsonResponse({'status': 'ok'})

        middleware = ErrorHandlingMiddleware(dummy_get_response)
        factory = RequestFactory()
        request = factory.get('/test/')

        exception = ValidationError("Invalid data")
        response = middleware.process_exception(request, exception)

        assert response.status_code == 400
        assert b'Validation error' in response.content

    def test_process_exception_database_error(self):
        """Test handling of DatabaseError"""
        def dummy_get_response(request):
            return JsonResponse({'status': 'ok'})

        middleware = ErrorHandlingMiddleware(dummy_get_response)
        factory = RequestFactory()
        request = factory.get('/test/')

        exception = DatabaseError("DB connection failed")
        response = middleware.process_exception(request, exception)

        assert response.status_code == 500
        assert b'Database error' in response.content

    def test_process_exception_generic(self):
        """Test handling of generic exceptions"""
        def dummy_get_response(request):
            return JsonResponse({'status': 'ok'})

        middleware = ErrorHandlingMiddleware(dummy_get_response)
        factory = RequestFactory()
        request = factory.get('/test/')

        exception = RuntimeError("Something went wrong")
        response = middleware.process_exception(request, exception)

        assert response.status_code == 500
        assert b'Internal server error' in response.content


class TestUtilityFunctions:
    """Test utility functions"""

    def test_get_client_ip_with_x_forwarded_for(self):
        """Test IP extraction from X-Forwarded-For header"""
        factory = RequestFactory()
        request = factory.get('/test/', HTTP_X_FORWARDED_FOR='1.2.3.4, 5.6.7.8')

        ip = get_client_ip(request)
        assert ip == '1.2.3.4'

    def test_get_client_ip_with_remote_addr(self):
        """Test IP extraction from REMOTE_ADDR"""
        factory = RequestFactory()
        request = factory.get('/test/')
        request.META['REMOTE_ADDR'] = '9.8.7.6'

        ip = get_client_ip(request)
        assert ip == '9.8.7.6'


class TestScanErrorHandler:
    """Test ScanErrorHandler"""

    def test_handle_detector_error(self):
        """Test handling detector errors"""
        result = ScanErrorHandler.handle_detector_error(
            scan_id=123,
            detector_name="xss_detector",
            exception=ValueError("Invalid payload")
        )

        assert result['detector'] == "xss_detector"
        assert result['error_type'] == "ValueError"
        assert 'Invalid payload' in result['error_message']

    def test_handle_timeout_error(self):
        """Test handling timeout errors"""
        result = ScanErrorHandler.handle_timeout_error(
            scan_id=456,
            detector_name="sql_detector",
            timeout_seconds=30
        )

        assert result['detector'] == "sql_detector"
        assert result['timeout'] == 30
        assert 'timeout' in result['reason'].lower()


class TestValidationHelper:
    """Test ValidationHelper"""

    def test_validate_url_valid_http(self):
        """Test URL validation with valid HTTP URL"""
        is_valid, error = ValidationHelper.validate_url("http://example.com")
        assert is_valid is True
        assert error is None

    def test_validate_url_valid_https(self):
        """Test URL validation with valid HTTPS URL"""
        is_valid, error = ValidationHelper.validate_url("https://example.com/path")
        assert is_valid is True
        assert error is None

    def test_validate_url_empty(self):
        """Test URL validation with empty URL"""
        is_valid, error = ValidationHelper.validate_url("")
        assert is_valid is False
        assert "required" in error.lower()

    def test_validate_url_no_scheme(self):
        """Test URL validation without scheme"""
        is_valid, error = ValidationHelper.validate_url("example.com")
        assert is_valid is False
        assert "scheme" in error.lower()

    def test_validate_url_invalid_scheme(self):
        """Test URL validation with invalid scheme"""
        is_valid, error = ValidationHelper.validate_url("ftp://example.com")
        assert is_valid is False
        assert "HTTP" in error or "HTTPS" in error

    def test_validate_url_localhost_blocked(self):
        """Test URL validation blocks localhost"""
        is_valid, error = ValidationHelper.validate_url("http://localhost")
        assert is_valid is False
        assert "localhost" in error.lower() or "internal" in error.lower()

    def test_sanitize_input_normal(self):
        """Test input sanitization with normal text"""
        result = ValidationHelper.sanitize_input("  Hello World  ")
        assert result == "Hello World"

    def test_sanitize_input_null_bytes(self):
        """Test input sanitization removes null bytes"""
        result = ValidationHelper.sanitize_input("Hello\x00World")
        assert result == "HelloWorld"

    def test_sanitize_input_max_length(self):
        """Test input sanitization enforces max length"""
        long_text = "A" * 2000
        result = ValidationHelper.sanitize_input(long_text, max_length=100)
        assert len(result) == 100

    def test_sanitize_input_empty(self):
        """Test input sanitization with empty string"""
        result = ValidationHelper.sanitize_input("")
        assert result == ""

    def test_sanitize_input_none(self):
        """Test input sanitization with None"""
        result = ValidationHelper.sanitize_input(None)
        assert result == ""

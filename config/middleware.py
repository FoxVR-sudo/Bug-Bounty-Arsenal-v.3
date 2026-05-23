"""
Custom middleware and authentication classes for BugBounty Arsenal.
"""
import os
from time import perf_counter

from django.conf import settings
from rest_framework.authentication import SessionAuthentication


class DisableCSRFForAPIMiddleware:
    """
    Disable CSRF protection for API endpoints.

    API endpoints use JWT authentication and don't need CSRF protection.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Exempt all /api/ endpoints from CSRF verification
        if request.path.startswith('/api/'):
            setattr(request, '_dont_enforce_csrf_checks', True)

        response = self.get_response(request)
        return response


class CsrfExemptSessionAuthentication(SessionAuthentication):
    """
    SessionAuthentication without CSRF checks for API endpoints.

    This allows browser-based clients to use session authentication
    without needing CSRF tokens, which is safe when combined with
    proper CORS configuration.
    """

    def enforce_csrf(self, request):
        # Do not enforce CSRF checks
        return


class SecurityHeadersMiddleware:
    """Add modern security headers.

    Django's built-in SecurityMiddleware covers many headers (HSTS, nosniff,
    referrer policy, X-Frame-Options). This middleware complements it with
    COOP/CORP and Permissions-Policy, and optionally CSP.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        response.setdefault('Cross-Origin-Opener-Policy', os.getenv('SECURE_COOP', 'same-origin'))
        response.setdefault('Cross-Origin-Resource-Policy', os.getenv('SECURE_CORP', 'same-site'))
        response.setdefault(
            'Permissions-Policy',
            os.getenv(
                'PERMISSIONS_POLICY',
                'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
            ),
        )

        # CSP can be disruptive if enabled without tuning. Keep it opt-in.
        if not settings.DEBUG and os.getenv('CSP_ENABLED', 'False') == 'True':
            csp_value = os.getenv(
                'CSP', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
            if os.getenv('CSP_REPORT_ONLY', 'True') == 'True':
                response.setdefault('Content-Security-Policy-Report-Only', csp_value)
            else:
                response.setdefault('Content-Security-Policy', csp_value)

        return response


class ActivityAuditMiddleware:
    """Persist a best-effort audit trail for application requests."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        started_at = perf_counter()

        try:
            response = self.get_response(request)
        except Exception as exc:
            duration_ms = int((perf_counter() - started_at) * 1000)
            from scans.audit import audit_request_event

            audit_request_event(request, duration_ms=duration_ms, exception=exc)
            raise

        duration_ms = int((perf_counter() - started_at) * 1000)
        from scans.audit import audit_request_event

        audit_request_event(request, response=response, duration_ms=duration_ms)
        return response

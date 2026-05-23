from __future__ import annotations

import os

from django.conf import settings
from django.db import connection
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status


def _db_ok() -> tuple[bool, str]:
    try:
        connection.ensure_connection()
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


def _broker_ok() -> tuple[bool, str]:
    try:
        from kombu import Connection

        conn = Connection(settings.CELERY_BROKER_URL)
        conn.connect()
        conn.release()
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


def _stripe_config_ok() -> tuple[bool, str]:
    key = str(getattr(settings, 'STRIPE_SECRET_KEY', '') or '').strip()
    if not key:
        return False, 'missing'
    if not key.startswith('sk_'):
        return False, 'invalid_format'
    # Do not validate against Stripe here (external dependency).
    return True, 'ok'


def _sendgrid_config_ok() -> tuple[bool, str]:
    # Backwards-compatible name: historically we exposed this as "sendgrid".
    # Now we consider any configured SMTP provider (generic/Mailtrap/SendGrid) as valid.
    backend = str(getattr(settings, 'EMAIL_BACKEND', '') or '').strip()
    if backend == 'django.core.mail.backends.smtp.EmailBackend':
        host = str(getattr(settings, 'EMAIL_HOST', '') or '').strip()
        user = str(getattr(settings, 'EMAIL_HOST_USER', '') or '').strip()
        password = str(getattr(settings, 'EMAIL_HOST_PASSWORD', '') or '').strip()
        if host and user and password:
            return True, 'ok'
        return False, 'incomplete_smtp_config'

    # Neither SMTP nor SendGrid API key
    key = str(getattr(settings, 'SENDGRID_API_KEY', '') or '').strip()
    if key:
        return True, 'ok'
    return False, 'not_configured'


def _frontend_url_ok() -> tuple[bool, str]:
    url = str(getattr(settings, 'FRONTEND_URL', '') or '').strip()
    if not url:
        return False, 'missing'
    if not getattr(settings, 'DEBUG', False) and ('localhost' in url or '127.0.0.1' in url):
        return False, 'points_to_localhost'
    return True, 'ok'


@api_view(["GET"])
def healthz_view(request):
    """Liveness probe.

    Intentionally shallow: should not depend on external services.
    """
    return Response({"status": "ok", "timestamp": timezone.now().isoformat()})


@api_view(["GET"])
def readyz_view(request):
    """Readiness probe.

    Checks DB always.
    Broker checks are gated by HEALTH_CHECK_BROKER in production; in DEBUG you can also force with ?broker=1.
    Returns 503 if required dependencies are unhealthy.
    """
    broker_enabled = os.getenv("HEALTH_CHECK_BROKER", "false").lower() in {"1", "true", "yes", "on"}
    requested_broker = request.query_params.get("broker") in {"1", "true", "yes", "on"}

    # In production, don't allow public query params to force broker checks.
    # This avoids noisy 503s if a liveness script probes ?broker=1 while broker is
    # intentionally private or temporarily unavailable.
    if settings.DEBUG:
        check_broker = requested_broker or broker_enabled
    else:
        check_broker = broker_enabled

    db_ok, db_detail = _db_ok()
    broker_ok, broker_detail = True, "skipped"
    if check_broker:
        broker_ok, broker_detail = _broker_ok()

    stripe_ok, stripe_detail = _stripe_config_ok()
    sendgrid_ok, sendgrid_detail = _sendgrid_config_ok()
    frontend_ok, frontend_detail = _frontend_url_ok()

    ok = db_ok and broker_ok

    payload = {
        "status": "ok" if ok else "unhealthy",
        "components": {
            "database": "ok" if db_ok else "unhealthy",
            "broker": "ok" if broker_ok else "unhealthy" if check_broker else "skipped",
            "stripe": "ok" if stripe_ok else "unconfigured",
            "sendgrid": "ok" if sendgrid_ok else "unconfigured",
            "frontend_url": "ok" if frontend_ok else "unconfigured",
        },
        "build": {
            "version": os.getenv('APP_VERSION', '') or None,
            "commit": os.getenv('GIT_COMMIT', '') or os.getenv('RENDER_GIT_COMMIT', '') or None,
        },
        "timestamp": timezone.now().isoformat(),
    }

    if settings.DEBUG:
        payload["details"] = {
            "database": db_detail,
            "broker": broker_detail,
            "stripe": stripe_detail,
            "sendgrid": sendgrid_detail,
            "frontend_url": frontend_detail,
        }

    return Response(payload, status=status.HTTP_200_OK if ok else status.HTTP_503_SERVICE_UNAVAILABLE)

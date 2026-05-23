"""Centralized audit logging helpers for site activity."""

from __future__ import annotations

import logging
from typing import Any, Mapping

from django.http import HttpRequest, HttpResponse
from django.urls import Resolver404, resolve

from utils.request_ip import get_client_ip

from .models import AuditLog

logger = logging.getLogger(__name__)

_SENSITIVE_KEYS = {
    'access',
    'access_token',
    'api_key',
    'authorization',
    'captcha_token',
    'code',
    'csrfmiddlewaretoken',
    'otp',
    'password',
    'refresh',
    'refresh_token',
    'secret',
    'token',
    'turnstile_token',
}

_EXCLUDED_PATH_PREFIXES = (
    '/media/',
    '/static/',
)

_EXCLUDED_PATHS = {
    '/favicon.ico',
    '/healthz/',
    '/readyz/',
}


def _truncate(value: Any, limit: int = 300) -> str:
    text = str(value or '')
    if len(text) <= limit:
        return text
    return f'{text[:limit]}...'


def sanitize_mapping(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    if not payload:
        return {}

    sanitized: dict[str, Any] = {}
    for raw_key, raw_value in payload.items():
        key = str(raw_key)
        if key.lower() in _SENSITIVE_KEYS:
            sanitized[key] = '[redacted]'
            continue

        if isinstance(raw_value, (list, tuple)):
            sanitized[key] = [_truncate(item) for item in list(raw_value)[:20]]
            continue

        if isinstance(raw_value, dict):
            sanitized[key] = sanitize_mapping(raw_value)
            continue

        sanitized[key] = _truncate(raw_value)

    return sanitized


def should_audit_request(request: HttpRequest) -> bool:
    path = str(getattr(request, 'path', '') or '')

    if not path:
        return False

    if path in _EXCLUDED_PATHS:
        return False

    if any(path.startswith(prefix) for prefix in _EXCLUDED_PATH_PREFIXES):
        return False

    # Avoid infra noise from the compose healthcheck.
    if path == '/api/schema/':
        return False

    return True


def _resolve_request_view(request: HttpRequest) -> tuple[str, str]:
    try:
        match = resolve(request.path_info)
    except Resolver404:
        return '', ''

    return (match.view_name or '', match.route or '')


def _request_extra_data(
    request: HttpRequest,
    *,
    response: HttpResponse | None = None,
    duration_ms: int | None = None,
    exception: Exception | None = None,
) -> dict[str, Any]:
    view_name, route = _resolve_request_view(request)

    content_length_raw = request.META.get('CONTENT_LENGTH')
    try:
        content_length = int(content_length_raw) if content_length_raw else 0
    except (TypeError, ValueError):
        content_length = 0

    extra_data: dict[str, Any] = {
        'path': request.path,
        'method': request.method,
        'view_name': view_name,
        'route': route,
        'query_params': sanitize_mapping(request.GET),
        'content_type': str(request.META.get('CONTENT_TYPE', '') or ''),
        'content_length': content_length,
        'referer': _truncate(request.META.get('HTTP_REFERER', '')),
        'origin': _truncate(request.META.get('HTTP_ORIGIN', '')),
        'is_api': request.path.startswith('/api/'),
        'is_admin': request.path.startswith('/admin/') or '/bba-' in request.path,
    }

    if response is not None:
        extra_data['status_code'] = response.status_code
        location = response.headers.get('Location') if hasattr(response, 'headers') else None
        if location:
            extra_data['redirect_to'] = _truncate(location)

    if duration_ms is not None:
        extra_data['duration_ms'] = int(duration_ms)

    user = getattr(request, 'user', None)
    if getattr(user, 'is_authenticated', False):
        extra_data['actor_role'] = (
            'superuser'
            if getattr(user, 'is_superuser', False)
            else 'admin'
            if getattr(user, 'is_admin', False)
            else 'staff'
            if getattr(user, 'is_staff', False)
            else 'user'
        )

    if exception is not None:
        extra_data['exception_type'] = exception.__class__.__name__
        extra_data['exception_message'] = _truncate(exception)

    return extra_data


def create_audit_log(
    *,
    event_type: str,
    description: str,
    request: HttpRequest | None = None,
    user=None,
    extra_data: Mapping[str, Any] | None = None,
) -> None:
    audit_user = user
    ip_address = None
    user_agent = ''

    if request is not None:
        if audit_user is None:
            request_user = getattr(request, 'user', None)
            if getattr(request_user, 'is_authenticated', False):
                audit_user = request_user
        ip_address = get_client_ip(request)
        user_agent = str(request.META.get('HTTP_USER_AGENT', '') or '')

    try:
        AuditLog.objects.create(
            user=audit_user,
            event_type=event_type[:100],
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            extra_data=dict(extra_data or {}),
        )
    except Exception:
        logger.exception('Failed to create audit log entry for %s', event_type)


def audit_request_event(
    request: HttpRequest,
    *,
    response: HttpResponse | None = None,
    duration_ms: int | None = None,
    exception: Exception | None = None,
) -> None:
    if not should_audit_request(request):
        return

    status_code = getattr(response, 'status_code', 500 if exception else None)
    if exception is not None:
        event_type = 'http.exception'
    else:
        event_type = f'http.{request.method.lower()}'

    description = f'{request.method} {request.path}'
    if status_code is not None:
        description = f'{description} -> {status_code}'

    create_audit_log(
        event_type=event_type,
        description=description,
        request=request,
        extra_data=_request_extra_data(
            request,
            response=response,
            duration_ms=duration_ms,
            exception=exception,
        ),
    )

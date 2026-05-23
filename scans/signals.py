"""Authentication lifecycle audit signals."""

from __future__ import annotations

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from .audit import create_audit_log, sanitize_mapping


@receiver(user_logged_in)
def audit_user_logged_in(sender, request, user, **kwargs):
    create_audit_log(
        event_type='auth.login',
        description='Successful user login',
        request=request,
        user=user,
        extra_data={
            'email': getattr(user, 'email', ''),
        },
    )


@receiver(user_logged_out)
def audit_user_logged_out(sender, request, user, **kwargs):
    audit_user = user if getattr(user, 'is_authenticated', False) else None
    create_audit_log(
        event_type='auth.logout',
        description='User logout',
        request=request,
        user=audit_user,
        extra_data={
            'email': getattr(audit_user, 'email', ''),
        },
    )


@receiver(user_login_failed)
def audit_user_login_failed(sender, credentials, request, **kwargs):
    attempted_identity = ''
    if isinstance(credentials, dict):
        attempted_identity = str(
            credentials.get('username')
            or credentials.get('email')
            or credentials.get('identifier')
            or ''
        )

    create_audit_log(
        event_type='auth.login_failed',
        description='Failed login attempt',
        request=request,
        extra_data={
            'attempted_identity': attempted_identity,
            'credentials': sanitize_mapping(credentials or {}),
        },
    )

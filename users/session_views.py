from __future__ import annotations

from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


def _get_token_models():
    """Import SimpleJWT blacklist models lazily.

    This project enables token_blacklist, but importing lazily keeps this module
    safe in environments where it is disabled.
    """

    from rest_framework_simplejwt.token_blacklist.models import (  # type: ignore
        BlacklistedToken,
        OutstandingToken,
    )

    return OutstandingToken, BlacklistedToken


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def sessions_list_view(request):
    """List active refresh-token sessions for the current user."""

    OutstandingToken, _BlacklistedToken = _get_token_models()
    now = timezone.now()

    tokens = (
        OutstandingToken.objects.filter(user=request.user, expires_at__gt=now)
        .exclude(blacklistedtoken__isnull=False)
        .order_by("-created_at")
    )

    results = [
        {
            "jti": t.jti,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        }
        for t in tokens
    ]

    return Response({"results": results}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def sessions_revoke_view(request):
    """Revoke a single session by refresh token JTI."""

    jti = (request.data or {}).get("jti")
    if not jti:
        return Response({"error": "jti is required"}, status=status.HTTP_400_BAD_REQUEST)

    OutstandingToken, BlacklistedToken = _get_token_models()

    token = OutstandingToken.objects.filter(user=request.user, jti=jti).first()
    if not token:
        return Response({"error": "Session not found"}, status=status.HTTP_404_NOT_FOUND)

    BlacklistedToken.objects.get_or_create(token=token)

    return Response({"message": "Session revoked"}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def sessions_revoke_all_view(request):
    """Revoke all active sessions for the current user."""

    OutstandingToken, BlacklistedToken = _get_token_models()
    now = timezone.now()

    tokens = (
        OutstandingToken.objects.filter(user=request.user, expires_at__gt=now)
        .exclude(blacklistedtoken__isnull=False)
        .order_by("-created_at")
    )

    revoked = 0
    for token in tokens:
        _obj, created = BlacklistedToken.objects.get_or_create(token=token)
        if created:
            revoked += 1

    return Response({"revoked": revoked}, status=status.HTTP_200_OK)

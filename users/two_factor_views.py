from django.utils import timezone
from drf_spectacular.utils import OpenApiExample, extend_schema
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .two_factor import (
    build_provisioning_uri,
    generate_backup_codes,
    generate_totp_secret,
    hash_backup_codes,
    verify_two_factor,
)


@extend_schema(
    summary="Get 2FA status",
    tags=["Authentication"],
    responses={200: {"type": "object"}},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def two_factor_status_view(request):
    user = request.user
    return Response(
        {
            "enabled": bool(getattr(user, "two_factor_enabled", False)),
            "has_backup_codes": bool(getattr(user, "two_factor_backup_codes", []) or []),
        },
        status=status.HTTP_200_OK,
    )


@extend_schema(
    summary="Start 2FA setup",
    description="Generates a new TOTP secret for the authenticated user and returns the provisioning URI.",
    tags=["Authentication"],
    responses={200: {"type": "object"}},
    examples=[
        OpenApiExample(
            "Setup response",
            value={
                "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                "otpauth_url": "otpauth://totp/BugBounty%20Arsenal:user%40example.com?...",
            },
        )
    ],
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def two_factor_setup_view(request):
    user = request.user

    secret = generate_totp_secret()
    user.two_factor_secret = secret
    user.two_factor_enabled = False
    user.two_factor_confirmed_at = None
    user.two_factor_backup_codes = []
    user.save(
        update_fields=[
            "two_factor_secret",
            "two_factor_enabled",
            "two_factor_confirmed_at",
            "two_factor_backup_codes",
        ]
    )

    otpauth_url = build_provisioning_uri(email=user.email, secret=secret)

    return Response(
        {
            "secret": secret,
            "otpauth_url": otpauth_url,
        },
        status=status.HTTP_200_OK,
    )


@extend_schema(
    summary="Confirm 2FA setup",
    description="Verifies the provided TOTP code; if valid, enables 2FA and returns backup codes (shown once).",
    tags=["Authentication"],
    request={
        "application/json": {
            "type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"],
        }
    },
    responses={200: {"type": "object"}, 400: {"type": "object"}},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def two_factor_confirm_view(request):
    user = request.user

    if not user.two_factor_secret:
        return Response(
            {"detail": "2FA setup has not been started."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    code = request.data.get("code", "")
    result = verify_two_factor(
        secret=user.two_factor_secret,
        backup_codes=user.two_factor_backup_codes or [],
        code=code,
    )

    if not result.ok or result.used_backup_code:
        # Setup confirmation must use TOTP, not backup codes
        return Response(
            {"detail": "Invalid authentication code."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    backup_codes_plain = generate_backup_codes(count=10, length=10)
    user.two_factor_enabled = True
    user.two_factor_confirmed_at = timezone.now()
    user.two_factor_backup_codes = hash_backup_codes(backup_codes_plain)
    user.save(
        update_fields=[
            "two_factor_enabled",
            "two_factor_confirmed_at",
            "two_factor_backup_codes",
        ]
    )

    return Response(
        {"enabled": True, "backup_codes": backup_codes_plain},
        status=status.HTTP_200_OK,
    )


@extend_schema(
    summary="Disable 2FA",
    description="Disables 2FA after verifying password + current 2FA code (TOTP or backup code).",
    tags=["Authentication"],
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "password": {"type": "string"},
                "code": {"type": "string"},
            },
            "required": ["password", "code"],
        }
    },
    responses={200: {"type": "object"}, 400: {"type": "object"}, 403: {"type": "object"}},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def two_factor_disable_view(request):
    user = request.user

    if not user.two_factor_enabled or not user.two_factor_secret:
        return Response({"detail": "2FA is not enabled."}, status=status.HTTP_400_BAD_REQUEST)

    password = request.data.get("password", "")
    code = request.data.get("code", "")

    if not user.check_password(password):
        return Response({"detail": "Invalid password."}, status=status.HTTP_403_FORBIDDEN)

    result = verify_two_factor(
        secret=user.two_factor_secret,
        backup_codes=user.two_factor_backup_codes or [],
        code=code,
    )
    if not result.ok:
        return Response({"detail": "Invalid authentication code."}, status=status.HTTP_400_BAD_REQUEST)

    # Invalidate used backup code (if any) before disabling
    if result.used_backup_code and result.backup_code_index is not None:
        try:
            codes = list(user.two_factor_backup_codes or [])
            codes.pop(result.backup_code_index)
            user.two_factor_backup_codes = codes
        except Exception:
            pass

    user.two_factor_enabled = False
    user.two_factor_secret = None
    user.two_factor_confirmed_at = None
    user.two_factor_backup_codes = []
    user.save(
        update_fields=[
            "two_factor_enabled",
            "two_factor_secret",
            "two_factor_confirmed_at",
            "two_factor_backup_codes",
        ]
    )

    return Response({"enabled": False}, status=status.HTTP_200_OK)


@extend_schema(
    summary="Regenerate 2FA backup codes",
    description="Generates a new set of backup codes after verifying password + current 2FA code.",
    tags=["Authentication"],
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "password": {"type": "string"},
                "code": {"type": "string"},
            },
            "required": ["password", "code"],
        }
    },
    responses={200: {"type": "object"}, 400: {"type": "object"}, 403: {"type": "object"}},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def two_factor_regenerate_backup_codes_view(request):
    user = request.user

    if not user.two_factor_enabled or not user.two_factor_secret:
        return Response({"detail": "2FA is not enabled."}, status=status.HTTP_400_BAD_REQUEST)

    password = request.data.get("password", "")
    code = request.data.get("code", "")

    if not user.check_password(password):
        return Response({"detail": "Invalid password."}, status=status.HTTP_403_FORBIDDEN)

    result = verify_two_factor(
        secret=user.two_factor_secret,
        backup_codes=user.two_factor_backup_codes or [],
        code=code,
    )
    if not result.ok:
        return Response({"detail": "Invalid authentication code."}, status=status.HTTP_400_BAD_REQUEST)

    # Invalidate used backup code (if any)
    if result.used_backup_code and result.backup_code_index is not None:
        try:
            codes = list(user.two_factor_backup_codes or [])
            codes.pop(result.backup_code_index)
            user.two_factor_backup_codes = codes
            user.save(update_fields=["two_factor_backup_codes"])
        except Exception:
            pass

    backup_codes_plain = generate_backup_codes(count=10, length=10)
    user.two_factor_backup_codes = hash_backup_codes(backup_codes_plain)
    user.save(update_fields=["two_factor_backup_codes"])

    return Response({"backup_codes": backup_codes_plain}, status=status.HTTP_200_OK)

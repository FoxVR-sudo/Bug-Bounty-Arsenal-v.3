from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from users.throttles import JwtLoginRateThrottle
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from .two_factor import verify_two_factor


class TwoFactorTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Extends JWT login to require a 2FA code if the user has 2FA enabled."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Optional field, only enforced when user.two_factor_enabled=True
        self.fields["otp"] = serializers.CharField(required=False, allow_blank=True, write_only=True)

    def validate(self, attrs):
        data = super().validate(attrs)

        user = getattr(self, "user", None)
        if user and getattr(user, "two_factor_enabled", False):
            code = attrs.get("otp")
            if not code:
                raise AuthenticationFailed(
                    {"detail": "Two-factor code required", "two_factor_required": True},
                    code="two_factor_required",
                )

            result = verify_two_factor(
                secret=getattr(user, "two_factor_secret", None),
                backup_codes=getattr(user, "two_factor_backup_codes", []) or [],
                code=code,
            )
            if not result.ok:
                raise AuthenticationFailed("Invalid two-factor code", code="invalid_two_factor")

            # Invalidate used backup code
            if result.used_backup_code and result.backup_code_index is not None:
                try:
                    codes = list(user.two_factor_backup_codes or [])
                    codes.pop(result.backup_code_index)
                    user.two_factor_backup_codes = codes
                    user.save(update_fields=["two_factor_backup_codes"])
                except Exception:
                    pass

        return data


class TwoFactorTokenObtainPairView(TokenObtainPairView):
    serializer_class = TwoFactorTokenObtainPairSerializer
    throttle_classes = [JwtLoginRateThrottle]

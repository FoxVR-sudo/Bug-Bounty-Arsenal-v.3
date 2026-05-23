import pyotp
import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
class TestTwoFactorAPI:
    @pytest.mark.api
    def test_2fa_setup_and_confirm(self, authenticated_client, test_user):
        setup_url = reverse("two-factor-setup")
        res = authenticated_client.post(setup_url, {}, format="json")
        assert res.status_code == status.HTTP_200_OK
        assert "secret" in res.data
        assert "otpauth_url" in res.data

        test_user.refresh_from_db()
        assert test_user.two_factor_enabled is False
        assert test_user.two_factor_secret

        code = pyotp.TOTP(test_user.two_factor_secret).now()
        confirm_url = reverse("two-factor-confirm")
        res2 = authenticated_client.post(confirm_url, {"code": code}, format="json")
        assert res2.status_code == status.HTTP_200_OK
        assert res2.data.get("enabled") is True
        assert isinstance(res2.data.get("backup_codes"), list)
        assert len(res2.data.get("backup_codes")) == 10

        test_user.refresh_from_db()
        assert test_user.two_factor_enabled is True
        assert test_user.two_factor_confirmed_at is not None
        assert isinstance(test_user.two_factor_backup_codes, list)
        assert len(test_user.two_factor_backup_codes) == 10

    @pytest.mark.api
    def test_jwt_login_requires_otp_when_2fa_enabled(self, api_client, test_user):
        # Enable 2FA directly for test
        secret = pyotp.random_base32()
        test_user.two_factor_secret = secret
        test_user.two_factor_enabled = True
        test_user.two_factor_backup_codes = []
        test_user.save(update_fields=["two_factor_secret", "two_factor_enabled", "two_factor_backup_codes"])

        url = reverse("token_obtain_pair")

        # Missing OTP should be rejected
        res = api_client.post(url, {"email": test_user.email, "password": "testpass123"}, format="json")
        assert res.status_code == status.HTTP_401_UNAUTHORIZED
        assert str(res.data.get("two_factor_required")).lower() == "true"

        # With OTP should succeed
        otp = pyotp.TOTP(secret).now()
        res2 = api_client.post(
            url,
            {"email": test_user.email, "password": "testpass123", "otp": otp},
            format="json",
        )
        assert res2.status_code == status.HTTP_200_OK
        assert "access" in res2.data
        assert "refresh" in res2.data

    @pytest.mark.api
    def test_backup_code_login_is_one_time(self, authenticated_client, api_client, test_user):
        # Setup + confirm to get backup codes
        setup_url = reverse("two-factor-setup")
        authenticated_client.post(setup_url, {}, format="json")
        test_user.refresh_from_db()

        confirm_url = reverse("two-factor-confirm")
        code = pyotp.TOTP(test_user.two_factor_secret).now()
        res = authenticated_client.post(confirm_url, {"code": code}, format="json")
        assert res.status_code == status.HTTP_200_OK
        backup_codes = res.data.get("backup_codes")
        assert backup_codes

        backup = backup_codes[0]

        # Use backup code to login via JWT endpoint
        url = reverse("token_obtain_pair")
        res2 = api_client.post(
            url,
            {"email": test_user.email, "password": "testpass123", "otp": backup},
            format="json",
        )
        assert res2.status_code == status.HTTP_200_OK

        # Backup code should be invalidated (count decreases)
        test_user.refresh_from_db()
        assert len(test_user.two_factor_backup_codes) == 9

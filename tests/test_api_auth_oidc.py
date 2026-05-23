import pytest
from django.urls import reverse
from rest_framework import status
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestOIDCLogin:
    @pytest.mark.api
    def test_oidc_login_creates_user_and_returns_jwt(self, api_client, settings, monkeypatch):
        settings.OIDC_JWKS_URL = "https://issuer.example.com/jwks"
        settings.OIDC_ISSUER = "https://issuer.example.com/"
        settings.OIDC_AUDIENCE = "client-id"

        import jwt

        class _DummyKey:
            key = "dummy"

        class _DummyJWKClient:
            def __init__(self, url):
                self.url = url

            def get_signing_key_from_jwt(self, token):
                return _DummyKey()

        def _dummy_decode(token, key, algorithms, audience=None, issuer=None, options=None):
            return {
                "email": "oidc.user@example.com",
                "given_name": "OIDC",
                "family_name": "User",
            }

        monkeypatch.setattr(jwt, "PyJWKClient", _DummyJWKClient)
        monkeypatch.setattr(jwt, "decode", _dummy_decode)

        url = reverse("auth-oidc-login")
        res = api_client.post(url, {"id_token": "dummy.token.value"}, format="json")

        assert res.status_code == status.HTTP_200_OK
        assert "access" in res.data
        assert "refresh" in res.data
        assert res.data["user"]["email"] == "oidc.user@example.com"
        assert User.objects.filter(email__iexact="oidc.user@example.com").exists()

    @pytest.mark.api
    def test_oidc_login_requires_config(self, api_client, settings):
        settings.OIDC_JWKS_URL = None

        url = reverse("auth-oidc-login")
        res = api_client.post(url, {"id_token": "dummy"}, format="json")

        assert res.status_code == status.HTTP_501_NOT_IMPLEMENTED

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken


@pytest.mark.api
class TestSessionManagementAPI:
    def test_sessions_list_and_revoke(self, authenticated_client, test_user):
        # Create two refresh tokens to represent two active sessions.
        refresh1 = RefreshToken.for_user(test_user)
        RefreshToken.for_user(test_user)

        list_url = reverse('auth-sessions')
        listed = authenticated_client.get(list_url)
        assert listed.status_code == status.HTTP_200_OK
        assert 'results' in listed.data
        assert len(listed.data['results']) == 2

        revoke_url = reverse('auth-sessions-revoke')
        revoked = authenticated_client.post(revoke_url, {'jti': refresh1['jti']}, format='json')
        assert revoked.status_code == status.HTTP_200_OK

        listed2 = authenticated_client.get(list_url)
        assert listed2.status_code == status.HTTP_200_OK
        assert len(listed2.data['results']) == 1

        # Revoke all remaining sessions.
        revoke_all_url = reverse('auth-sessions-revoke-all')
        revoked_all = authenticated_client.post(revoke_all_url, {}, format='json')
        assert revoked_all.status_code == status.HTTP_200_OK
        assert revoked_all.data.get('revoked') == 1

        listed3 = authenticated_client.get(list_url)
        assert listed3.status_code == status.HTTP_200_OK
        assert len(listed3.data['results']) == 0

    def test_sessions_revoke_requires_jti(self, authenticated_client):
        revoke_url = reverse('auth-sessions-revoke')
        response = authenticated_client.post(revoke_url, {}, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'error' in response.data

"""
API tests for authentication endpoints
"""
import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class TestAuthenticationAPI:
    """Test authentication endpoints"""

    @pytest.mark.api
    def test_user_registration(self, api_client, free_plan):
        """Test new user registration"""
        url = reverse('auth-signup')
        data = {
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'password_confirm': 'securepass123',
            'first_name': 'New',
            'middle_name': 'Middle',
            'last_name': 'User',
            'phone': '+12345678901',
            'accept_terms': True,
            'accept_privacy': True,
            'accept_disclaimer': True,
            'accept_aup': True,
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert 'access' in response.data
        assert 'refresh' in response.data
        assert User.objects.filter(email='newuser@example.com').exists()

    @pytest.mark.api
    def test_registration_duplicate_email(self, api_client, test_user):
        """Test registration with duplicate email fails"""
        url = reverse('auth-signup')
        data = {
            'email': test_user.email,  # Duplicate
            'password': 'securepass123',
            'password_confirm': 'securepass123',
            'first_name': 'Another',
            'last_name': 'User'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.api
    def test_registration_password_mismatch(self, api_client):
        """Test registration with mismatched passwords"""
        url = reverse('auth-signup')
        data = {
            'email': 'new@example.com',
            'password': 'password123',
            'password_confirm': 'different456',
            'first_name': 'New',
            'last_name': 'User'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.api
    def test_user_login(self, api_client, test_user):
        """Test user login with correct credentials"""
        url = reverse('token_obtain_pair')
        data = {
            'email': test_user.email,
            'password': 'testpass123'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data

    @pytest.mark.api
    def test_login_wrong_password(self, api_client, test_user):
        """Test login with wrong password fails"""
        url = reverse('token_obtain_pair')
        data = {
            'email': test_user.email,
            'password': 'wrongpassword'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.api
    def test_token_refresh(self, api_client, test_user):
        """Test JWT token refresh"""
        refresh = RefreshToken.for_user(test_user)

        url = reverse('token_refresh')
        data = {
            'refresh': str(refresh)
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data

    @pytest.mark.api
    def test_logout_requires_authentication(self, api_client, test_user):
        """Logout should be protected (no anonymous blacklisting)."""
        refresh = RefreshToken.for_user(test_user)

        url = reverse('auth-logout')
        response = api_client.post(url, {'refresh': str(refresh)}, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.api
    def test_logout_blacklists_refresh_token(self, authenticated_client, test_user):
        """Logout should blacklist refresh token so it can't be reused."""
        refresh = RefreshToken.for_user(test_user)

        logout_url = reverse('auth-logout')
        logout_response = authenticated_client.post(logout_url, {'refresh': str(refresh)}, format='json')
        assert logout_response.status_code == status.HTTP_200_OK

        # Using the same refresh token again should fail.
        refresh_url = reverse('auth-refresh')
        refresh_response = authenticated_client.post(refresh_url, {'refresh': str(refresh)}, format='json')
        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.api
    def test_get_current_user(self, authenticated_client, test_user):
        """Test retrieving current user profile"""
        url = reverse('current-user')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == test_user.email

    @pytest.mark.api
    def test_update_user_profile(self, authenticated_client, test_user):
        """Test updating user profile"""
        url = reverse('api:user-detail', kwargs={'pk': test_user.id})
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': test_user.email,
        }

        response = authenticated_client.patch(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['first_name'] == 'Updated'

        # Verify in database
        test_user.refresh_from_db()
        assert test_user.first_name == 'Updated'


class TestPhoneVerification:
    """Test phone verification endpoints"""

    @pytest.mark.api
    def test_send_verification_code(self, authenticated_client):
        """Test sending SMS verification code"""
        url = reverse('send-phone-verification')
        from unittest.mock import patch

        with patch(
            'users.api_views.PhoneVerificationService.send_verification_code',
            return_value=(True, '123456', 'Verification code sent successfully'),
        ):
            response = authenticated_client.post(url, {'phone': '+15555550123'}, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data.get('success') is True

    @pytest.mark.api
    def test_verify_phone_correct_code(self, authenticated_client, test_user):
        """Test verifying phone with correct code"""
        from django.utils import timezone
        from datetime import timedelta
        from django.contrib.auth.hashers import make_password

        test_user.phone_verification_code = make_password('123456')
        test_user.phone_verification_expires = timezone.now() + timedelta(minutes=10)
        test_user.phone_verified = False
        test_user.save(update_fields=['phone_verification_code', 'phone_verification_expires', 'phone_verified'])

        url = reverse('verify-phone-code')
        data = {'code': '123456'}

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK

        # Verify user is marked as verified
        test_user.refresh_from_db()
        assert test_user.phone_verified is True

    @pytest.mark.api
    def test_verify_phone_wrong_code(self, authenticated_client, test_user):
        """Test verifying phone with wrong code"""
        from django.utils import timezone
        from datetime import timedelta
        from django.contrib.auth.hashers import make_password

        test_user.phone_verification_code = make_password('123456')
        test_user.phone_verification_expires = timezone.now() + timedelta(minutes=10)
        test_user.phone_verified = False
        test_user.save(update_fields=['phone_verification_code', 'phone_verification_expires', 'phone_verified'])

        url = reverse('verify-phone-code')
        data = {'code': '999999'}

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

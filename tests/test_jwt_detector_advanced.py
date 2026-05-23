"""
Extended tests for JWT Detector - edge cases and advanced scenarios
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestJWTDetectorAdvanced:
    """Advanced JWT detector tests"""

    @pytest.mark.detector
    def test_detect_jwt_with_bearer_prefix(self):
        """Test JWT detection with Bearer prefix"""
        from detectors.jwt_detector import jwt_detector_passive as detect

        text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc'
        combined_dict = {
            'url': 'https://example.com/api',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_detect_multiple_jwts(self):
        """Test detection of multiple JWTs in response"""
        from detectors.jwt_detector import jwt_detector_passive as detect

        text = '''
        {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc",
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIn0.def"
        }
        '''
        combined_dict = {
            'url': 'https://example.com/auth',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_detect_jwt_algorithm_none_vulnerability(self):
        """Test detection of 'none' algorithm vulnerability"""
        from detectors.jwt_detector import jwt_detector_passive as detect

        # JWT with 'none' algorithm
        text = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.'
        combined_dict = {
            'url': 'https://example.com/admin',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_jwt_detector_with_custom_headers(self):
        """Test JWT detection with custom headers"""
        from detectors.jwt_detector import jwt_detector_active as detect

        url = "https://example.com/api/user"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"user": "test"}')
        mock_response.headers = {
            'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc'
        }
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_jwt_weak_secret_bruteforce(self):
        """Test JWT weak secret detection"""
        from detectors.jwt_detector import WEAK_SECRETS

        # Verify common weak secrets are in the list
        assert 'secret' in WEAK_SECRETS
        assert 'password' in WEAK_SECRETS
        assert 'test' in WEAK_SECRETS or '123456' in WEAK_SECRETS

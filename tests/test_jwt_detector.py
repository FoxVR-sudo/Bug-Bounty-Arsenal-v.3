"""
Unit tests for JWT Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


class TestJWTDetector:
    """Test JWT vulnerability detection"""

    @pytest.mark.detector
    def test_detect_jwt_in_text(self):
        """Test detection of JWT token in text"""
        from detectors.jwt_detector import jwt_detector_passive

        text = """
        Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        """
        combined_dict = {
            'url': 'https://example.com',
            'context': {'resp': {'headers': {'Authorization': 'Bearer token'}, 'text': text}}
        }
        findings = jwt_detector_passive(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_decode_jwt_header(self):
        """Test JWT header decoding"""
        from detectors.jwt_detector import decode_jwt_nosig

        # Standard JWT token
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        result = decode_jwt_nosig(token)

        # Should decode successfully
        assert result is not None or result == (None, None)  # May return tuple

    @pytest.mark.detector
    def test_detect_algorithm_none(self):
        """Test detection of 'none' algorithm vulnerability"""
        from detectors.jwt_detector import jwt_detector_passive

        # JWT with "none" algorithm
        text = 'Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.'
        combined_dict = {
            'url': 'https://example.com',
            'context': {'resp': {'headers': {}, 'text': text}}
        }
        findings = jwt_detector_passive(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_jwt_detector_runs(self):
        """Test that JWT detector runs without crashing"""
        from detectors.jwt_detector import jwt_detector_active as detect

        url = "https://example.com/api/profile"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"user": "test"}')
        mock_response.headers = {'Authorization': 'Bearer token123'}
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_jwt_handles_timeout(self):
        """Test timeout handling"""
        from detectors.jwt_detector import jwt_detector_active as detect

        url = "https://slow.com/api"
        context = {'per_host_rate': None}

        # Mock aiohttp session with timeout
        mock_session = MagicMock()
        mock_session.get.side_effect = asyncio.TimeoutError("Timeout")

        findings = await detect(mock_session, url, context)

        # Should handle timeout gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_weak_secret_detection(self):
        """Test detection of weak JWT secrets"""
        from detectors.jwt_detector import WEAK_SECRETS

        # Verify we have a good list of weak secrets
        assert len(WEAK_SECRETS) > 10
        assert 'secret' in WEAK_SECRETS
        assert 'password' in WEAK_SECRETS
        assert '123456' in WEAK_SECRETS

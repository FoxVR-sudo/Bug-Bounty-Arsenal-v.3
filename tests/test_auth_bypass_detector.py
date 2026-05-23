"""
Unit tests for Auth Bypass Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestAuthBypassDetector:
    """Test Authentication Bypass detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_auth_bypass_detector_runs(self):
        """Test that Auth Bypass detector runs without crashing"""
        from detectors.auth_bypass_detector import auth_bypass_detector

        url = "https://example.com/admin"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.text = AsyncMock(return_value="Unauthorized")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await auth_bypass_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_auth_bypass_handles_errors(self):
        """Test error handling"""
        from detectors.auth_bypass_detector import auth_bypass_detector

        url = "https://error.com/admin"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await auth_bypass_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

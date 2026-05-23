"""
Unit tests for OAuth Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestOAuthDetector:
    """Test OAuth vulnerability detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_oauth_detector_runs(self):
        """Test that OAuth detector runs without crashing"""
        from detectors.oauth_detector import oauth_detector_active as oauth_detector

        url = "https://example.com/oauth/authorize"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="OAuth authorization page")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await oauth_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_oauth_handles_errors(self):
        """Test error handling"""
        from detectors.oauth_detector import oauth_detector_active as oauth_detector

        url = "https://error.com/oauth"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await oauth_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

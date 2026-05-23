"""
Unit tests for Open Redirect Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


class TestOpenRedirectDetector:
    """Test Open Redirect vulnerability detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_open_redirect_detector_runs(self):
        """Test that Open Redirect detector runs without crashing"""
        from detectors.open_redirect_detector import open_redirect_detector as detect

        url = "https://example.com/redirect?url=https://google.com"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 302
        mock_response.headers = {'Location': 'https://evil.com'}
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_open_redirect_handles_timeout(self):
        """Test timeout handling"""
        from detectors.open_redirect_detector import open_redirect_detector as detect

        url = "https://slow.com/redirect"
        context = {'per_host_rate': None}

        # Mock aiohttp session with timeout
        mock_session = MagicMock()
        mock_session.get.side_effect = asyncio.TimeoutError("Timeout")

        findings = await detect(mock_session, url, context)

        # Should handle timeout gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_open_redirect_handles_errors(self):
        """Test error handling"""
        from detectors.open_redirect_detector import open_redirect_detector as detect

        url = "https://error.com/redirect"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)


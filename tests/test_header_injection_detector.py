"""
Unit tests for Header Injection Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


class TestHeaderInjectionDetector:
    """Test Header Injection detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_header_injection_detector_runs(self):
        """Test that Header Injection detector runs without crashing"""
        from detectors.header_injection_detector import detect_header_injection as detect

        url = "https://example.com/page"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = AsyncMock(return_value="<html>Page</html>")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_header_injection_handles_timeout(self):
        """Test timeout handling"""
        from detectors.header_injection_detector import detect_header_injection as detect

        url = "https://slow.com/page"
        context = {'per_host_rate': None}

        # Mock aiohttp session with timeout
        mock_session = MagicMock()
        mock_session.get.side_effect = asyncio.TimeoutError("Timeout")

        findings = await detect(mock_session, url, context)

        # Should handle timeout gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_header_injection_handles_errors(self):
        """Test error handling"""
        from detectors.header_injection_detector import detect_header_injection as detect

        url = "https://error.com/page"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)


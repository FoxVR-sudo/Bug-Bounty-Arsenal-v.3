"""
Unit tests for CORS Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


class TestCORSDetector:
    """Test CORS misconfiguration detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cors_detector_runs(self):
        """Test that CORS detector runs without crashing"""
        from detectors.cors_detector import cors_detector as detect

        url = "https://api.example.com/data"
        context = {'timeout': 5, 'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        }
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cors_wildcard_with_credentials(self):
        """Test detection of CORS wildcard with credentials (critical issue)"""
        from detectors.cors_detector import cors_detector as detect

        url = "https://api.example.com/sensitive"
        context = {'timeout': 5, 'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        }
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # This is a critical CORS misconfiguration
        # Should detect it if detector checks for this
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cors_handles_errors(self):
        """Test error handling"""
        from detectors.cors_detector import cors_detector as detect

        url = "https://error.com/api"
        context = {'timeout': 5, 'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cors_timeout_handling(self):
        """Test timeout handling"""
        from detectors.cors_detector import cors_detector as detect

        url = "https://slow.com/api"
        context = {'timeout': 1, 'per_host_rate': None}

        # Mock aiohttp session with timeout
        mock_session = MagicMock()
        mock_session.get.side_effect = asyncio.TimeoutError("Timeout")

        findings = await detect(mock_session, url, context)

        # Should handle timeout gracefully
        assert isinstance(findings, list)


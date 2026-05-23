"""
Unit tests for Rate Limit Bypass Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestRateLimitBypassDetector:
    """Test Rate Limit Bypass detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_rate_limit_bypass_detector_runs(self):
        """Test that Rate Limit Bypass detector runs without crashing"""
        from detectors.rate_limit_bypass_detector import rate_limit_bypass_detector

        url = "https://api.example.com/endpoint"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"data": "success"}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await rate_limit_bypass_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_rate_limit_bypass_handles_errors(self):
        """Test error handling"""
        from detectors.rate_limit_bypass_detector import rate_limit_bypass_detector

        url = "https://error.com/api"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await rate_limit_bypass_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

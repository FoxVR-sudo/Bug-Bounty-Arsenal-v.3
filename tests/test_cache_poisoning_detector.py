"""
Unit tests for Cache Poisoning Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestCachePoisoningDetector:
    """Test Cache Poisoning vulnerability detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cache_poisoning_detector_runs(self):
        """Test that Cache Poisoning detector runs without crashing"""
        from detectors.cache_poisoning_detector import cache_poisoning_detector

        url = "https://example.com/page"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Cache-Control': 'public, max-age=3600'}
        mock_response.text = AsyncMock(return_value="<html>Page</html>")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await cache_poisoning_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cache_poisoning_handles_errors(self):
        """Test error handling"""
        from detectors.cache_poisoning_detector import cache_poisoning_detector

        url = "https://error.com/page"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await cache_poisoning_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

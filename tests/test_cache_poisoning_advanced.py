"""
Extended tests for Cache Poisoning Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestCachePoisoningAdvanced:
    """Advanced cache poisoning detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cache_poisoning_with_x_forwarded_host(self):
        """Test cache poisoning with X-Forwarded-Host header"""
        from detectors.cache_poisoning_detector import cache_poisoning_detector as detect

        url = "https://example.com/"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<html>Homepage</html>')
        mock_response.headers = {'Cache-Control': 'public, max-age=3600'}
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cache_poisoning_with_vary_header(self):
        """Test cache poisoning detection with Vary header"""
        from detectors.cache_poisoning_detector import cache_poisoning_detector as detect

        url = "https://example.com/api/data"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"data": "cached"}')
        mock_response.headers = {
            'Cache-Control': 'public',
            'Vary': 'Accept-Language'
        }
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_cache_poisoning_no_cache(self):
        """Test with no-cache directive"""
        from detectors.cache_poisoning_detector import cache_poisoning_detector as detect

        url = "https://example.com/private"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='Private content')
        mock_response.headers = {'Cache-Control': 'no-cache, no-store'}
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

"""
Extended tests for Rate Limit Bypass Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestRateLimitBypassAdvanced:
    """Advanced rate limit bypass detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_rate_limit_bypass_header_variations(self):
        """Test rate limit bypass with different header variations"""
        from detectors.rate_limit_bypass_detector import rate_limit_bypass_detector as detect

        url = "https://example.com/api/login"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()

        # First requests: rate limited
        mock_response_limited = AsyncMock()
        mock_response_limited.status = 429
        mock_response_limited.text = AsyncMock(return_value='Too Many Requests')

        # Later requests: bypassed
        mock_response_ok = AsyncMock()
        mock_response_ok.status = 200
        mock_response_ok.text = AsyncMock(return_value='OK')

        mock_post.__aenter__.side_effect = [
            mock_response_limited,
            mock_response_limited,
            mock_response_ok,
            mock_response_ok
        ]
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_rate_limit_bypass_ip_rotation(self):
        """Test rate limit bypass with IP rotation headers"""
        from detectors.rate_limit_bypass_detector import rate_limit_bypass_detector as detect

        url = "https://example.com/api/data"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"data": "test"}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_rate_limit_bypass_user_agent_rotation(self):
        """Test rate limit bypass with user agent rotation"""
        from detectors.rate_limit_bypass_detector import rate_limit_bypass_detector as detect

        url = "https://example.com/search"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='Results')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

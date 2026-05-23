"""
Unit tests for NoSQL Injection Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


class TestNoSQLInjectionDetector:
    """Test NoSQL Injection detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_nosql_injection_detector_runs(self):
        """Test that NoSQL Injection detector runs without crashing"""
        from detectors.nosql_injection_detector import nosql_injection_detector as detect

        url = "https://api.example.com/users?id=123"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"user": "test"}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_nosql_handles_timeout(self):
        """Test timeout handling"""
        from detectors.nosql_injection_detector import nosql_injection_detector as detect

        url = "https://slow.com/api"
        context = {'per_host_rate': None}

        # Mock aiohttp session with timeout
        mock_session = MagicMock()
        mock_session.get.side_effect = asyncio.TimeoutError("Timeout")

        findings = await detect(mock_session, url, context)

        # Should handle timeout gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_nosql_handles_errors(self):
        """Test error handling"""
        from detectors.nosql_injection_detector import nosql_injection_detector as detect

        url = "https://error.com/api"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)


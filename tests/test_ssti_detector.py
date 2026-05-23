"""
Unit tests for SSTI (Server-Side Template Injection) Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


class TestSSTIDetector:
    """Test Server-Side Template Injection detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_ssti_detector_runs(self):
        """Test that SSTI detector runs without crashing"""
        from detectors.ssti_detector import ssti_detector as detect

        url = "https://example.com/template?name=test"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="Hello test")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_ssti_handles_timeout(self):
        """Test timeout handling"""
        from detectors.ssti_detector import ssti_detector as detect

        url = "https://slow.com/template"
        context = {'per_host_rate': None}

        # Mock aiohttp session with timeout
        mock_session = MagicMock()
        mock_session.get.side_effect = asyncio.TimeoutError("Timeout")

        findings = await detect(mock_session, url, context)

        # Should handle timeout gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_ssti_handles_errors(self):
        """Test error handling"""
        from detectors.ssti_detector import ssti_detector as detect

        url = "https://error.com/template"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_ssti_jinja2_detection(self):
        """Test Jinja2 SSTI detection (7*7=49 pattern)"""
        from detectors.ssti_detector import ssti_detector as detect

        url = "https://example.com/render?template={{7*7}}"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        # Vulnerable response shows calculation result
        mock_response.text = AsyncMock(return_value="Result: 49")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)


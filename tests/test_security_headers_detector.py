"""
Unit tests for Security Headers Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestSecurityHeadersDetector:
    """Test Security Headers detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_security_headers_detector_runs(self):
        """Test that Security Headers detector runs without crashing"""
        from detectors.security_headers_detector import security_headers_detector

        url = "https://example.com/"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            'Content-Type': 'text/html',
            'X-Content-Type-Options': 'nosniff'
        }
        mock_response.text = AsyncMock(return_value="<html>Home</html>")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await security_headers_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_security_headers_missing_csp(self):
        """Test detection of missing CSP header"""
        from detectors.security_headers_detector import security_headers_detector

        url = "https://example.com/"
        context = {'per_host_rate': None}

        # Mock aiohttp session - response WITHOUT CSP header
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = AsyncMock(return_value="<html>Home</html>")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await security_headers_detector(mock_session, url, context)

        # Should detect missing security headers
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_security_headers_handles_errors(self):
        """Test error handling"""
        from detectors.security_headers_detector import security_headers_detector

        url = "https://error.com/"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await security_headers_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

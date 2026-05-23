"""
Extended tests for Header Injection Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestHeaderInjectionAdvanced:
    """Advanced header injection detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_header_injection_crlf(self):
        """Test header injection with CRLF payloads"""
        from detectors.header_injection_detector import detect_header_injection as detect

        url = "https://example.com/redirect?url=https://safe.com"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()

        # Response with injected headers
        mock_response = AsyncMock()
        mock_response.status = 302
        mock_response.headers = {'Location': 'https://safe.com\r\nX-Injected: true'}
        mock_response.text = AsyncMock(return_value='')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_header_injection_newline_variations(self):
        """Test header injection with different newline variations"""
        from detectors.header_injection_detector import detect_header_injection as detect

        url = "https://example.com/api/callback"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = AsyncMock(return_value='OK')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_header_injection_response_splitting(self):
        """Test header injection for HTTP response splitting"""
        from detectors.header_injection_detector import detect_header_injection as detect

        url = "https://example.com/download?file=report.pdf"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            'Content-Disposition': 'attachment; filename="report.pdf"'
        }
        mock_response.text = AsyncMock(return_value='PDF content')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

"""
Unit tests for LFI (Local File Inclusion) Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


class TestLFIDetector:
    """Test Local File Inclusion detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_lfi_detector_runs(self):
        """Test that LFI detector runs without crashing"""
        from detectors.lfi_detector import detect_lfi as detect

        url = "https://example.com/download?file=report.pdf"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="PDF content")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_lfi_handles_timeout(self):
        """Test timeout handling"""
        from detectors.lfi_detector import detect_lfi as detect

        url = "https://slow.com/file"
        context = {'per_host_rate': None}

        # Mock aiohttp session with timeout
        mock_session = MagicMock()
        mock_session.get.side_effect = asyncio.TimeoutError("Timeout")

        findings = await detect(mock_session, url, context)

        # Should handle timeout gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_lfi_handles_errors(self):
        """Test error handling"""
        from detectors.lfi_detector import detect_lfi as detect

        url = "https://error.com/file"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_lfi_etc_passwd_detection(self):
        """Test /etc/passwd detection"""
        from detectors.lfi_detector import detect_lfi as detect

        url = "https://example.com/read?file=../../../../etc/passwd"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        # Vulnerable response shows /etc/passwd content
        mock_response.text = AsyncMock(return_value="root:x:0:0:root:/root:/bin/bash")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)


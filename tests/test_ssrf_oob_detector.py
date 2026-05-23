"""
Unit tests for SSRF OOB Advanced Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from detectors.ssrf_oob_advanced_detector import detect


class TestSSRFOOBDetector:
    """Test SSRF Out-of-Band detection functionality"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_detector_runs_without_errors(self):
        """Test that detector runs without crashing"""
        url = "https://example.com/proxy?url="
        config = {'timeout': 5}

        # Mock HTTP requests to avoid actual network calls
        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_get = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='OK')
            mock_get.__aenter__.return_value = mock_response
            mock_session.get.return_value = mock_get
            MockSession.return_value.__aenter__.return_value = mock_session

            findings = await detect(url, config)

            # Detector should return a list
            assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_detector_handles_timeout(self):
        """Test graceful handling of timeouts"""
        url = "https://slow-server.com/fetch"
        config = {'timeout': 1}

        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_session.get.side_effect = asyncio.TimeoutError("Timeout")
            MockSession.return_value.__aenter__.return_value = mock_session

            findings = await detect(url, config)

            # Should handle timeout gracefully
            assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_detector_handles_errors(self):
        """Test error handling"""
        url = "https://error.com/proxy"
        config = {'timeout': 5}

        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_session.get.side_effect = Exception("Network error")
            MockSession.return_value.__aenter__.return_value = mock_session

            findings = await detect(url, config)

            # Should handle errors gracefully
            assert isinstance(findings, list)

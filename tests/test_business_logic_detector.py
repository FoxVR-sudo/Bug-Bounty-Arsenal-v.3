"""
Unit tests for Business Logic Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from detectors.business_logic_detector import detect


class TestBusinessLogicDetector:
    """Test Business Logic vulnerability detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_detector_runs_without_errors(self):
        """Test that detector runs without crashing"""
        url = "https://example.com/checkout"
        config = {'timeout': 5}

        # Mock all HTTP requests to avoid actual network calls
        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_post = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='OK')
            mock_response.json = AsyncMock(return_value={'success': True})
            mock_post.__aenter__.return_value = mock_response
            mock_session.post.return_value = mock_post
            MockSession.return_value.__aenter__.return_value = mock_session

            findings = await detect(url, config)

            # Detector should return a list
            assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_detector_handles_timeout(self):
        """Test graceful handling of timeouts"""
        url = "https://slow-shop.com/checkout"
        config = {'timeout': 1}

        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_session.post.side_effect = asyncio.TimeoutError("Timeout")
            MockSession.return_value.__aenter__.return_value = mock_session

            findings = await detect(url, config)

            # Should handle timeout gracefully
            assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_detector_handles_errors(self):
        """Test error handling"""
        url = "https://error.com/checkout"
        config = {'timeout': 5}

        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_session.post.side_effect = Exception("Network error")
            MockSession.return_value.__aenter__.return_value = mock_session

            findings = await detect(url, config)

            # Should handle errors gracefully
            assert isinstance(findings, list)

"""
Unit tests for Fuzz Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestFuzzDetector:
    """Test Fuzz detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_fuzz_detector_runs(self):
        """Test that Fuzz detector runs without crashing"""
        from detectors.fuzz_detector import detect_fuzz as detect

        url = "https://example.com/api/search?q=test"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"results": []}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_fuzz_detector_handles_errors(self):
        """Test error handling"""
        from detectors.fuzz_detector import detect_fuzz as detect

        url = "https://error.com/fuzz"
        context = {'per_host_rate': None}

        # Mock session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

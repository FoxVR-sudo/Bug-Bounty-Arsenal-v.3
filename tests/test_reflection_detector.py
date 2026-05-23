"""
Unit tests for Reflection Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestReflectionDetector:
    """Test Reflection detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_reflection_detector_runs(self):
        """Test that Reflection detector runs without crashing"""
        from detectors.reflection_detector import detect_reflections as reflection_detector

        url = "https://example.com/search?q=test"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="Search results for: test")
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await reflection_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_reflection_handles_errors(self):
        """Test error handling"""
        from detectors.reflection_detector import detect_reflections as reflection_detector

        url = "https://error.com/search"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await reflection_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

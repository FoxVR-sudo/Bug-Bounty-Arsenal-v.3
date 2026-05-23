"""
Unit tests for Prototype Pollution Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestPrototypePollutionDetector:
    """Test Prototype Pollution vulnerability detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_prototype_pollution_detector_runs(self):
        """Test that Prototype Pollution detector runs without crashing"""
        from detectors.prototype_pollution_detector import prototype_pollution_detector

        url = "https://api.example.com/update"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"status": "ok"}')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await prototype_pollution_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_prototype_pollution_handles_errors(self):
        """Test error handling"""
        from detectors.prototype_pollution_detector import prototype_pollution_detector

        url = "https://error.com/api"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("Network error")

        findings = await prototype_pollution_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

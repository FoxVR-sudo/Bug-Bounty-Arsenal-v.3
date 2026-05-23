"""
Unit tests for Race Condition Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestRaceConditionDetector:
    """Test Race Condition vulnerability detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_race_condition_detector_runs(self):
        """Test that Race Condition detector runs without crashing"""
        from detectors.race_condition_detector import race_condition_detector

        url = "https://api.example.com/transfer"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"status": "success"}')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await race_condition_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_race_condition_handles_errors(self):
        """Test error handling"""
        from detectors.race_condition_detector import race_condition_detector

        url = "https://error.com/api"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("Network error")

        findings = await race_condition_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

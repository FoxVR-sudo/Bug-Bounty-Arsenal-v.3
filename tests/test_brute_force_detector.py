"""
Unit tests for Brute Force Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestBruteForceDetector:
    """Test Brute Force attack detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_brute_force_detector_runs(self):
        """Test that Brute Force detector runs without crashing"""
        from detectors.brute_force_detector import brute_force_detector

        url = "https://example.com/login"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.text = AsyncMock(return_value="Invalid credentials")
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await brute_force_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_brute_force_handles_errors(self):
        """Test error handling"""
        from detectors.brute_force_detector import brute_force_detector

        url = "https://error.com/login"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("Network error")

        findings = await brute_force_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

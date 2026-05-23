"""
Unit tests for XXE (XML External Entity) Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestXXEDetector:
    """Test XXE vulnerability detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_xxe_detector_runs(self):
        """Test that XXE detector runs without crashing"""
        from detectors.xxe_detector import xxe_detector

        url = "https://api.example.com/parse-xml"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="<response>OK</response>")
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await xxe_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_xxe_handles_errors(self):
        """Test error handling"""
        from detectors.xxe_detector import xxe_detector

        url = "https://error.com/xml"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("Network error")

        findings = await xxe_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

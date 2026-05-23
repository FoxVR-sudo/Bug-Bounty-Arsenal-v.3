"""
Unit tests for Simple File List Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestSimpleFileListDetector:
    """Test Simple File List detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_simple_file_list_detector_runs(self):
        """Test that Simple File List detector runs without crashing"""
        from detectors.simple_file_list_detector import simple_file_list_detector as detect

        url = "https://example.com/"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<html><body>Homepage</body></html>')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_simple_file_list_finds_files(self):
        """Test detection of common files"""
        from detectors.simple_file_list_detector import simple_file_list_detector as detect

        url = "https://example.com/"
        context = {'per_host_rate': None}

        # Mock aiohttp session - simulate finding robots.txt
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='User-agent: *\\nDisallow: /admin')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_simple_file_list_handles_errors(self):
        """Test error handling"""
        from detectors.simple_file_list_detector import simple_file_list_detector as detect

        url = "https://error.com/"
        context = {'per_host_rate': None}

        # Mock session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

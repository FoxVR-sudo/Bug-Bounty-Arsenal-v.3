"""
Unit tests for Directory Listing Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestDirListingDetector:
    """Test Directory Listing detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_dir_listing_detector_runs(self):
        """Test that Directory Listing detector runs without crashing"""
        from detectors.dir_listing_detector import dir_listing_detector as detect

        url = "https://example.com/uploads/"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<html><title>Index of /uploads</title></html>')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_dir_listing_handles_errors(self):
        """Test error handling"""
        from detectors.dir_listing_detector import dir_listing_detector as detect

        url = "https://error.com/dir/"
        context = {'per_host_rate': None}

        # Mock session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

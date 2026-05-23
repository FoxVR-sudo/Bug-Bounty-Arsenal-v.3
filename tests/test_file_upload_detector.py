"""
Unit tests for File Upload Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestFileUploadDetector:
    """Test File Upload vulnerability detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_file_upload_detector_runs(self):
        """Test that File Upload detector runs without crashing"""
        from detectors.file_upload_detector import file_upload_detector_active as file_upload_detector

        url = "https://example.com/upload"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="File uploaded successfully")
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await file_upload_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_file_upload_handles_errors(self):
        """Test error handling"""
        from detectors.file_upload_detector import file_upload_detector_active as file_upload_detector

        url = "https://error.com/upload"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("Network error")

        findings = await file_upload_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

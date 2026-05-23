"""
Unit tests for IDOR Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestIDORDetector:
    """Test IDOR (Insecure Direct Object Reference) detection"""

    @pytest.mark.detector
    def test_extract_numeric_ids_from_url(self):
        """Test extraction of numeric IDs from URL"""
        from detectors.idor_detector import extract_ids_from_url

        url = "https://example.com/api/users/123/profile"
        ids = extract_ids_from_url(url)

        assert len(ids) > 0
        assert any(id_info['type'] == 'numeric' and id_info['value'] == '123' for id_info in ids)

    @pytest.mark.detector
    def test_extract_uuid_from_url(self):
        """Test extraction of UUID from URL"""
        from detectors.idor_detector import extract_ids_from_url

        url = "https://example.com/documents/550e8400-e29b-41d4-a716-446655440000"
        ids = extract_ids_from_url(url)

        assert len(ids) > 0
        assert any(id_info['type'] == 'uuid' for id_info in ids)

    @pytest.mark.detector
    def test_extract_query_param_ids(self):
        """Test extraction of IDs from query parameters"""
        from detectors.idor_detector import extract_ids_from_url

        url = "https://example.com/view?user_id=456&doc=789"
        ids = extract_ids_from_url(url)

        assert len(ids) > 0
        # Should find IDs in query parameters
        assert any(id_info['location'] == 'query' for id_info in ids)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_idor_detector_runs(self):
        """Test that IDOR detector runs without crashing"""
        from detectors.idor_detector import idor_detector as detect

        url = "https://example.com/api/users/123"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='User Profile')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_idor_handles_errors(self):
        """Test error handling in IDOR detector"""
        from detectors.idor_detector import idor_detector as detect

        url = "https://error.com/users/123"
        context = {'per_host_rate': None}

        # Mock session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

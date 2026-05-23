"""
Extended tests for IDOR Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestIDORAdvanced:
    """Advanced IDOR (Insecure Direct Object Reference) detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_idor_sequential_id_manipulation(self):
        """Test IDOR with sequential ID manipulation"""
        from detectors.idor_detector import idor_detector as detect

        url = "https://example.com/api/users/123"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()

        # Response for user 123
        mock_response1 = AsyncMock()
        mock_response1.status = 200
        mock_response1.text = AsyncMock(return_value='{"user": {"id": 123, "email": "user123@example.com"}}')

        # Response for user 124 (should not be accessible)
        mock_response2 = AsyncMock()
        mock_response2.status = 200
        mock_response2.text = AsyncMock(return_value='{"user": {"id": 124, "email": "user124@example.com"}}')

        mock_get.__aenter__.side_effect = [mock_response1, mock_response2]
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_idor_uuid_manipulation(self):
        """Test IDOR with UUID manipulation"""
        from detectors.idor_detector import idor_detector as detect

        url = "https://example.com/api/documents/550e8400-e29b-41d4-a716-446655440000"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"document": {"id": "uuid", "title": "Secret"}}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_idor_parameter_pollution(self):
        """Test IDOR via parameter pollution"""
        from detectors.idor_detector import idor_detector as detect

        url = "https://example.com/profile?user_id=100"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"profile": {"user_id": 100}}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

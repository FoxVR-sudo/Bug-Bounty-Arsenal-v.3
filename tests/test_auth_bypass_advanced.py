"""
Extended tests for Auth Bypass Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestAuthBypassDetectorAdvanced:
    """Advanced auth bypass detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_auth_bypass_with_different_methods(self):
        """Test auth bypass with HTTP method manipulation"""
        from detectors.auth_bypass_detector import auth_bypass_detector as detect

        url = "https://example.com/admin"
        context = {'per_host_rate': None}

        mock_session = MagicMock()

        # Mock GET request (denied)
        mock_get = AsyncMock()
        mock_get_response = AsyncMock()
        mock_get_response.status = 403
        mock_get_response.text = AsyncMock(return_value='Forbidden')
        mock_get.__aenter__.return_value = mock_get_response
        mock_session.get.return_value = mock_get

        # Mock POST request (allowed)
        mock_post = AsyncMock()
        mock_post_response = AsyncMock()
        mock_post_response.status = 200
        mock_post_response.text = AsyncMock(return_value='Admin Panel')
        mock_post.__aenter__.return_value = mock_post_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_auth_bypass_header_manipulation(self):
        """Test auth bypass with header manipulation"""
        from detectors.auth_bypass_detector import auth_bypass_detector as detect

        url = "https://example.com/api/users"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"users": []}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_auth_bypass_path_traversal(self):
        """Test auth bypass with path traversal"""
        from detectors.auth_bypass_detector import auth_bypass_detector as detect

        url = "https://example.com/admin/../public/../admin"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='Admin')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

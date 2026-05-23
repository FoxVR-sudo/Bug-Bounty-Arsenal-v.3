"""
Unit tests for API Security Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestAPISecurityDetector:
    """Test API Security detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_api_security_detector_runs(self):
        """Test that API Security detector runs without crashing"""
        from detectors.api_security_detector import api_security_detector

        url = "https://api.example.com/v1/users"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.text = AsyncMock(return_value='{"users": []}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await api_security_detector(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_api_security_handles_errors(self):
        """Test error handling"""
        from detectors.api_security_detector import api_security_detector

        url = "https://error.com/api"
        context = {'per_host_rate': None}

        # Mock aiohttp session with error
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Network error")

        findings = await api_security_detector(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

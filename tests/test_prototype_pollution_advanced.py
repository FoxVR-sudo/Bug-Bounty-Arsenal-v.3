"""
Extended tests for Prototype Pollution Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestPrototypePollutionAdvanced:
    """Advanced prototype pollution detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_prototype_pollution_merge_payloads(self):
        """Test prototype pollution with merge operation payloads"""
        from detectors.prototype_pollution_detector import prototype_pollution_detector as detect

        url = "https://example.com/api/settings?config=test"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"status": "ok"}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get
        mock_session.post.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_prototype_pollution_nested_properties(self):
        """Test prototype pollution with nested property access"""
        from detectors.prototype_pollution_detector import prototype_pollution_detector as detect

        url = "https://example.com/user/profile"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"user": {"name": "test"}}')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_prototype_pollution_json_payloads(self):
        """Test prototype pollution with JSON payloads"""
        from detectors.prototype_pollution_detector import prototype_pollution_detector as detect

        url = "https://example.com/api/update"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{}')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

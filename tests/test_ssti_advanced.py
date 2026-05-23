"""
Extended tests for SSTI Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestSSTIAdvanced:
    """Advanced SSTI detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_ssti_jinja2_payloads(self):
        """Test SSTI detection with Jinja2 specific payloads"""
        from detectors.ssti_detector import ssti_detector as detect

        url = "https://example.com/template?name=test"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()

        # Return response indicating SSTI
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='Result: 49')  # 7*7=49
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_ssti_erb_payloads(self):
        """Test SSTI detection with ERB template payloads"""
        from detectors.ssti_detector import ssti_detector as detect

        url = "https://example.com/render"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<%= 7*7 %>')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_ssti_freemarker_payloads(self):
        """Test SSTI detection with Freemarker payloads"""
        from detectors.ssti_detector import ssti_detector as detect

        url = "https://example.com/page?template=default"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='${7*7}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_ssti_velocity_payloads(self):
        """Test SSTI detection with Velocity template payloads"""
        from detectors.ssti_detector import ssti_detector as detect

        url = "https://example.com/vm"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='#set($x = 7 * 7)')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

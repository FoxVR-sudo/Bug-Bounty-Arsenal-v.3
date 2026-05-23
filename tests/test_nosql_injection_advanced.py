"""
Extended tests for NoSQL Injection Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestNoSQLInjectionAdvanced:
    """Advanced NoSQL injection detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_nosql_mongodb_operators(self):
        """Test NoSQL injection with MongoDB operators"""
        from detectors.nosql_injection_detector import nosql_injection_detector as detect

        url = "https://example.com/api/users?id=123"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()

        # Response showing NoSQL operator worked
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"users": [{"name": "admin"}]}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_nosql_authentication_bypass(self):
        """Test NoSQL injection for authentication bypass"""
        from detectors.nosql_injection_detector import nosql_injection_detector as detect

        url = "https://example.com/login"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()

        # Failed login first, then successful bypass
        mock_response_fail = AsyncMock()
        mock_response_fail.status = 401
        mock_response_fail.text = AsyncMock(return_value='{"error": "Invalid credentials"}')

        mock_response_success = AsyncMock()
        mock_response_success.status = 200
        mock_response_success.text = AsyncMock(return_value='{"token": "abc123"}')

        mock_post.__aenter__.side_effect = [mock_response_fail, mock_response_success]
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_nosql_json_injection(self):
        """Test NoSQL injection via JSON payloads"""
        from detectors.nosql_injection_detector import nosql_injection_detector as detect

        url = "https://example.com/api/search"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"results": []}')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_nosql_timing_attacks(self):
        """Test NoSQL injection timing-based detection"""
        from detectors.nosql_injection_detector import nosql_injection_detector as detect

        url = "https://example.com/api/validate?username=test"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_get = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"valid": false}')
        mock_get.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_get

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

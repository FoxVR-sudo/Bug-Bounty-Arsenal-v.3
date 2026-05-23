"""
Unit tests for GraphQL Injection Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestGraphQLInjectionDetector:
    """Test GraphQL Injection detection"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_graphql_injection_detector_runs(self):
        """Test that GraphQL Injection detector runs without crashing"""
        from detectors.graphql_injection_detector import graphql_injection_detector as detect

        url = "https://example.com/graphql"
        context = {'per_host_rate': None}

        # Mock aiohttp session
        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"data": {"user": {}}}')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_graphql_injection_handles_errors(self):
        """Test error handling"""
        from detectors.graphql_injection_detector import graphql_injection_detector as detect

        url = "https://error.com/graphql"
        context = {'per_host_rate': None}

        # Mock session with error
        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("Network error")

        findings = await detect(mock_session, url, context)

        # Should handle errors gracefully
        assert isinstance(findings, list)

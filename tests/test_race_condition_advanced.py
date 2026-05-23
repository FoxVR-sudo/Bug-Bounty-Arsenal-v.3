"""
Extended tests for Race Condition Detector
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


class TestRaceConditionAdvanced:
    """Advanced race condition detector tests"""

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_race_condition_concurrent_requests(self):
        """Test race condition with concurrent requests"""
        from detectors.race_condition_detector import race_condition_detector as detect

        url = "https://example.com/api/balance/withdraw"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"success": true}')
        mock_post.__aenter__.return_value = mock_response
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_race_condition_state_change(self):
        """Test race condition in state-changing operations"""
        from detectors.race_condition_detector import race_condition_detector as detect

        url = "https://example.com/api/vote"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_post = AsyncMock()

        # Simulate varying responses
        responses = []
        for i in range(3):
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=f'{{"votes": {i+1}}}')
            responses.append(mock_response)

        mock_post.__aenter__.side_effect = responses
        mock_session.post.return_value = mock_post

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_race_condition_error_handling(self):
        """Test race condition detector error handling"""
        from detectors.race_condition_detector import race_condition_detector as detect

        url = "https://example.com/api/transfer"
        context = {'per_host_rate': None}

        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("Connection error")

        findings = await detect(mock_session, url, context)
        assert isinstance(findings, list)

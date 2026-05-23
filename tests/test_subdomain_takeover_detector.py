"""
Unit tests for Subdomain Takeover Detector
"""
import pytest


class TestSubdomainTakeoverDetector:
    """Test Subdomain Takeover detection"""

    @pytest.mark.detector
    def test_subdomain_takeover_detector_runs(self):
        """Test that Subdomain Takeover detector runs without crashing"""
        from detectors.subdomain_takeover_detector import subdomain_takeover_detector as detect

        url = "https://example.com/"

        # Mock response text
        text = '<html>Homepage</html>'
        combined_dict = {
            'url': url,
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_subdomain_takeover_handles_errors(self):
        """Test error handling"""
        from detectors.subdomain_takeover_detector import subdomain_takeover_detector as detect

        url = "https://abandoned.example.com/"

        # Mock error response
        text = ''
        combined_dict = {
            'url': url,
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should handle errors gracefully
        assert isinstance(findings, list)

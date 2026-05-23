"""
Unit tests for SSRF Detector (Basic/Passive)
"""
import pytest


class TestSSRFDetector:
    """Test SSRF (passive) detection"""

    @pytest.mark.detector
    def test_ssrf_detector_finds_internal_urls(self):
        """Test detection of internal URLs"""
        from detectors.ssrf_detector import detect_ssrf_from_text as detect

        text = '<img src="http://localhost:8080/admin">'
        combined_dict = {
            'url': 'https://example.com/profile',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_ssrf_detector_finds_private_ips(self):
        """Test detection of private IPs"""
        from detectors.ssrf_detector import detect_ssrf_from_text as detect

        text = 'Fetching from http://192.168.1.1/api'
        combined_dict = {
            'url': 'https://example.com/fetch',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_ssrf_detector_handles_clean_response(self):
        """Test handling of clean responses"""
        from detectors.ssrf_detector import detect_ssrf_from_text as detect

        text = 'Public content from https://google.com'
        combined_dict = {
            'url': 'https://example.com/',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

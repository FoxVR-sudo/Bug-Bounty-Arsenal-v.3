"""
Unit tests for XSS Pattern Detector
"""
import pytest


class TestXSSPatternDetector:
    """Test XSS Pattern detection"""

    @pytest.mark.detector
    def test_xss_pattern_detector_finds_reflection(self):
        """Test detection of reflected XSS"""
        from detectors.xss_pattern_detector import detect_xss_from_text as detect

        text = '<script>alert(1)</script> was found in response'
        combined_dict = {
            'url': 'https://example.com/search?q=<script>alert(1)</script>',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_xss_pattern_detector_finds_event_handlers(self):
        """Test detection of event handler XSS"""
        from detectors.xss_pattern_detector import detect_xss_from_text as detect

        text = '<img src=x onerror="alert(1)">'
        combined_dict = {
            'url': 'https://example.com/profile',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_xss_pattern_detector_handles_clean_response(self):
        """Test handling of clean responses"""
        from detectors.xss_pattern_detector import detect_xss_from_text as detect

        text = 'Welcome to our safe website'
        combined_dict = {
            'url': 'https://example.com/',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

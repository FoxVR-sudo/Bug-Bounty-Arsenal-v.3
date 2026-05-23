"""
Unit tests for XSS Pattern Detector
"""
import pytest
from detectors.xss_pattern_detector import detect_xss_from_text


class TestXSSPatternDetector:
    """Test XSS detection functionality"""

    @pytest.mark.detector
    def test_detect_script_tag(self):
        """Test detection of <script> tag"""
        text = "<html><script>alert('XSS')</script></html>"
        findings = detect_xss_from_text(text, {})

        assert len(findings) > 0
        assert any('XSS' in f.get('type', '') for f in findings)
        assert any('script' in f.get('evidence', '').lower() for f in findings)

    @pytest.mark.detector
    def test_detect_javascript_protocol(self):
        """Test detection of javascript: protocol"""
        text = '<a href="javascript:alert(1)">Click</a>'
        findings = detect_xss_from_text(text, {})

        assert len(findings) > 0
        assert any('XSS' in f.get('type', '') for f in findings)

    @pytest.mark.detector
    def test_detect_event_handlers(self):
        """Test detection of onerror/onload attributes"""
        text = '<img src=x onerror="alert(1)">'
        findings = detect_xss_from_text(text, {})

        assert len(findings) > 0
        assert any('XSS' in f.get('type', '') for f in findings)

    @pytest.mark.detector
    def test_no_xss_in_safe_text(self):
        """Test no false positive on safe HTML"""
        text = '<h1>Welcome</h1><p>This is safe content</p>'
        findings = detect_xss_from_text(text, {})

        # Should not detect XSS in safe HTML
        assert len(findings) == 0

    @pytest.mark.detector
    def test_detect_multiple_indicators(self):
        """Test detection of multiple XSS indicators"""
        text = '<script>alert(1)</script><img src=x onerror="alert(2)">'
        findings = detect_xss_from_text(text, {})

        # Should detect both indicators
        assert len(findings) >= 2

    @pytest.mark.detector
    def test_empty_text(self):
        """Test handling of empty text"""
        findings = detect_xss_from_text("", {})
        assert findings == []

        findings = detect_xss_from_text(None, {})
        assert findings == []

    @pytest.mark.detector
    def test_case_insensitive_detection(self):
        """Test that detection is case-insensitive"""
        text = '<SCRIPT>alert(1)</SCRIPT>'
        findings = detect_xss_from_text(text, {})

        assert len(findings) > 0

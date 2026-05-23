"""
Unit tests for CSRF Detector
"""
import pytest
from detectors.csrf_detector import csrf_detector_from_text


class TestCSRFDetector:
    """Test CSRF detection functionality"""

    @pytest.mark.detector
    def test_detect_form_without_csrf_token(self):
        """Test detection of form without CSRF token"""
        html = """
        <html>
        <form method="POST" action="/transfer">
            <input type="text" name="amount">
            <input type="text" name="to_account">
            <button type="submit">Transfer</button>
        </form>
        </html>
        """
        findings = csrf_detector_from_text(html, {})

        assert len(findings) > 0
        assert any('CSRF' in f.get('type', '') for f in findings)

    @pytest.mark.detector
    def test_no_detection_with_csrf_token(self):
        """Test no detection when CSRF token present"""
        html = """
        <form method="POST" action="/transfer">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="text" name="amount">
            <button type="submit">Transfer</button>
        </form>
        """
        findings = csrf_detector_from_text(html, {})

        # Should not detect CSRF when token is present
        assert len(findings) == 0

    @pytest.mark.detector
    def test_detect_csrf_variations(self):
        """Test detection with various CSRF token name variations"""
        # Test _csrf
        html1 = '<form method="POST"><input type="hidden" name="_csrf" value="token"></form>'
        findings1 = csrf_detector_from_text(html1, {})
        assert len(findings1) == 0

        # Test authenticity_token (Rails)
        html2 = '<form method="POST"><input name="authenticity_token" value="token"></form>'
        findings2 = csrf_detector_from_text(html2, {})
        assert len(findings2) == 0

        # Test csrf (generic)
        html3 = '<form method="POST"><input name="csrf" value="token"></form>'
        findings3 = csrf_detector_from_text(html3, {})
        assert len(findings3) == 0

    @pytest.mark.detector
    def test_multiple_forms(self):
        """Test detection of multiple forms"""
        html = """
        <form method="POST" action="/login">
            <input name="csrf_token" value="abc">
        </form>
        <form method="POST" action="/transfer">
            <input name="amount">
        </form>
        """
        findings = csrf_detector_from_text(html, {})

        # Should detect only the form without CSRF token
        assert len(findings) > 0

    @pytest.mark.detector
    def test_empty_text(self):
        """Test handling of empty text"""
        findings = csrf_detector_from_text("", {})
        assert findings == []

        findings = csrf_detector_from_text(None, {})
        assert findings == []

    @pytest.mark.detector
    def test_case_insensitive_detection(self):
        """Test case-insensitive CSRF token detection"""
        html = '<FORM method="POST"><INPUT name="CSRF_TOKEN" value="abc"></FORM>'
        findings = csrf_detector_from_text(html, {})

        # Should detect CSRF token regardless of case
        assert len(findings) == 0

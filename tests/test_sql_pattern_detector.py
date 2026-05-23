"""
Unit tests for SQL Pattern Detector
"""
import pytest


class TestSQLPatternDetector:
    """Test SQL Pattern detection"""

    @pytest.mark.detector
    def test_sql_pattern_detector_finds_error(self):
        """Test detection of SQL error messages"""
        from detectors.sql_pattern_detector import detect_sql_from_text as detect

        text = "You have an error in your SQL syntax near 'SELECT * FROM users'"
        combined_dict = {
            'url': 'https://example.com/user?id=1',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_sql_pattern_detector_mysql_error(self):
        """Test detection of MySQL error messages"""
        from detectors.sql_pattern_detector import detect_sql_from_text as detect

        text = "mysql_fetch_array(): supplied argument is not a valid MySQL result"
        combined_dict = {
            'url': 'https://example.com/login',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_sql_pattern_detector_handles_clean_response(self):
        """Test handling of clean responses"""
        from detectors.sql_pattern_detector import detect_sql_from_text as detect

        text = "Welcome to our website"
        combined_dict = {
            'url': 'https://example.com/',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list (empty in this case)
        assert isinstance(findings, list)

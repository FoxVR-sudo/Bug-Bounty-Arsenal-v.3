"""
Unit tests for SQL Pattern Detector
"""
import pytest
from detectors.sql_pattern_detector import detect_sql_from_text


class TestSQLPatternDetector:
    """Test SQL injection detection functionality"""

    @pytest.mark.detector
    def test_detect_mysql_error(self):
        """Test detection of MySQL syntax error"""
        text = "You have an error in your SQL syntax; check the manual"
        findings = detect_sql_from_text(text, {})

        assert len(findings) > 0
        assert any('SQL' in f.get('type', '') for f in findings)
        assert any('MySQL' in f.get('evidence', '') for f in findings)

    @pytest.mark.detector
    def test_detect_postgres_error(self):
        """Test detection of PostgreSQL error"""
        text = "ERROR: pg_query() error: syntax error at or near"
        findings = detect_sql_from_text(text, {})

        assert len(findings) > 0
        assert any('SQL' in f.get('type', '') for f in findings)

    @pytest.mark.detector
    def test_detect_mssql_error(self):
        """Test detection of MSSQL error"""
        text = "Unclosed quotation mark after the character string"
        findings = detect_sql_from_text(text, {})

        assert len(findings) > 0
        assert any('SQL' in f.get('type', '') for f in findings)

    @pytest.mark.detector
    def test_detect_oracle_error(self):
        """Test detection of Oracle error"""
        text = "quoted string not properly terminated"
        findings = detect_sql_from_text(text, {})

        assert len(findings) > 0
        assert any('SQL' in f.get('type', '') for f in findings)

    @pytest.mark.detector
    def test_detect_sqlite_error(self):
        """Test detection of SQLite error"""
        text = "SQLite error: near 'FROM': syntax error"
        findings = detect_sql_from_text(text, {})

        assert len(findings) > 0
        assert any('SQL' in f.get('type', '') for f in findings)

    @pytest.mark.detector
    def test_no_sql_in_safe_text(self):
        """Test no false positive on safe text"""
        text = "Welcome to our website. Please login to continue."
        findings = detect_sql_from_text(text, {})

        # Should not detect SQL in safe text
        assert len(findings) == 0

    @pytest.mark.detector
    def test_empty_text(self):
        """Test handling of empty text"""
        findings = detect_sql_from_text("", {})
        assert findings == []

        findings = detect_sql_from_text(None, {})
        assert findings == []

    @pytest.mark.detector
    def test_case_insensitive_detection(self):
        """Test that detection is case-insensitive"""
        text = "WARNING: MYSQL ERROR IN YOUR QUERY"
        findings = detect_sql_from_text(text, {})

        assert len(findings) > 0

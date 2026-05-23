"""
Unit tests for CVE Database Detector
"""
import pytest


class TestCVEDatabaseDetector:
    """Test CVE Database detection"""

    @pytest.mark.detector
    def test_cve_database_detector_instantiates(self):
        """Test that CVE Database detector class can be instantiated"""
        from detectors.cve_database_detector import CVEDatabaseDetector

        detector = CVEDatabaseDetector()

        # Should be an instance of the class
        assert detector is not None
        assert isinstance(detector, CVEDatabaseDetector)

    @pytest.mark.detector
    def test_cve_database_has_methods(self):
        """Test that detector has expected methods"""
        from detectors.cve_database_detector import CVEDatabaseDetector

        detector = CVEDatabaseDetector()

        # Should have common methods
        assert hasattr(detector, '__init__')


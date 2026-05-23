"""
Unit tests for Logging Configuration
"""
import logging
from utils.logging_config import (
    setup_logging,
    get_logger,
    log_security_event,
    log_scan_event,
    ColoredFormatter
)


class TestLoggingSetup:
    """Test logging setup functions"""

    def test_setup_logging(self):
        """Test logging setup"""
        setup_logging()

        # Verify logger is configured
        logger = logging.getLogger('bugbounty')
        assert logger is not None

    def test_setup_logging_debug_mode(self):
        """Test logging setup with debug mode"""
        setup_logging(debug=True)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_get_logger(self):
        """Test get_logger function"""
        logger = get_logger(__name__)
        assert logger is not None
        assert isinstance(logger, logging.Logger)

    def test_get_logger_with_custom_name(self):
        """Test get_logger with custom name"""
        logger = get_logger('custom.logger')
        assert logger.name == 'custom.logger'


class TestSecurityLogging:
    """Test security logging functions"""

    def test_log_security_event_basic(self):
        """Test logging security events"""
        # Should not raise exception
        log_security_event(
            event_type="authentication_success",
            user="testuser",
            ip="127.0.0.1"
        )

    def test_log_security_event_with_details(self):
        """Test logging security events with details"""
        log_security_event(
            event_type="permission_denied",
            user="baduser",
            ip="192.168.1.1",
            details={"resource": "/api/admin", "action": "DELETE"}
        )

    def test_log_security_event_anonymous(self):
        """Test logging security events for anonymous user"""
        log_security_event(
            event_type="failed_login",
            ip="10.0.0.1"
        )


class TestScanLogging:
    """Test scan logging functions"""

    def test_log_scan_event_basic(self):
        """Test logging scan events"""
        log_scan_event(
            scan_id=123,
            event_type="scan_started"
        )

    def test_log_scan_event_with_details(self):
        """Test logging scan events with details"""
        log_scan_event(
            scan_id=456,
            event_type="detector_completed",
            details="XSS detector found 3 vulnerabilities"
        )

    def test_log_scan_event_error(self):
        """Test logging scan errors"""
        log_scan_event(
            scan_id=789,
            event_type="scan_failed",
            details="Timeout during SSRF detection"
        )


class TestColoredFormatter:
    """Test ColoredFormatter"""

    def test_colored_formatter_creation(self):
        """Test creating ColoredFormatter"""
        formatter = ColoredFormatter(
            '%(asctime)s [%(levelname)s] %(message)s'
        )
        assert formatter is not None

    def test_colored_formatter_format_info(self):
        """Test formatting INFO level message"""
        formatter = ColoredFormatter('%(levelname)s: %(message)s')

        logger = logging.getLogger('test')
        record = logger.makeRecord(
            name='test',
            level=logging.INFO,
            fn='test.py',
            lno=10,
            msg='Test message',
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert 'Test message' in formatted

    def test_colored_formatter_format_error(self):
        """Test formatting ERROR level message"""
        formatter = ColoredFormatter('%(levelname)s: %(message)s')

        logger = logging.getLogger('test')
        record = logger.makeRecord(
            name='test',
            level=logging.ERROR,
            fn='test.py',
            lno=20,
            msg='Error occurred',
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert 'Error occurred' in formatted


class TestLoggerInstances:
    """Test getting different logger instances"""

    def test_get_security_logger(self):
        """Test getting security logger"""
        setup_logging()
        logger = logging.getLogger('security')
        assert logger is not None

    def test_get_scans_logger(self):
        """Test getting scans logger"""
        setup_logging()
        logger = logging.getLogger('scans')
        assert logger is not None

    def test_logger_hierarchy(self):
        """Test logger hierarchy"""
        logger1 = get_logger('app.module1')
        logger2 = get_logger('app.module2')

        assert logger1.name == 'app.module1'
        assert logger2.name == 'app.module2'

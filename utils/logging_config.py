"""
Production-ready logging configuration for BugBounty Arsenal
"""
import logging
import logging.handlers
from pathlib import Path

# Create logs directory
LOGS_DIR = Path(__file__).resolve().parent.parent / 'logs'
LOGS_DIR.mkdir(exist_ok=True)


class ColoredFormatter(logging.Formatter):
    """Colored log formatter for console output"""

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(debug=False):
    """
    Configure logging for the application

    Args:
        debug (bool): Enable debug logging
    """

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console Handler (colored)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    console_formatter = ColoredFormatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File Handler - General Log (rotating)
    general_log = LOGS_DIR / 'bugbounty_arsenal.log'
    file_handler = logging.handlers.RotatingFileHandler(
        general_log,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=10,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # File Handler - Error Log (errors only)
    error_log = LOGS_DIR / 'errors.log'
    error_handler = logging.handlers.RotatingFileHandler(
        error_log,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    root_logger.addHandler(error_handler)

    # File Handler - Security Log (authentication, authorization events)
    security_log = LOGS_DIR / 'security.log'
    security_handler = logging.handlers.RotatingFileHandler(
        security_log,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=10,
        encoding='utf-8'
    )
    security_handler.setLevel(logging.INFO)
    security_handler.setFormatter(file_formatter)

    # Add security handler to security logger
    security_logger = logging.getLogger('security')
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False

    # File Handler - Scan Log (detector execution logs)
    scan_log = LOGS_DIR / 'scans.log'
    scan_handler = logging.handlers.RotatingFileHandler(
        scan_log,
        maxBytes=50 * 1024 * 1024,  # 50 MB
        backupCount=20,
        encoding='utf-8'
    )
    scan_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    scan_handler.setFormatter(file_formatter)

    # Add scan handler to scan logger
    scan_logger = logging.getLogger('scans')
    scan_logger.addHandler(scan_handler)
    scan_logger.setLevel(logging.DEBUG if debug else logging.INFO)
    scan_logger.propagate = False

    # Suppress noisy third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('celery').setLevel(logging.WARNING)
    logging.getLogger('django.utils.autoreload').setLevel(logging.WARNING)

    logging.info("Logging system initialized")
    logging.info(f"Log directory: {LOGS_DIR}")


def get_logger(name):
    """
    Get a logger instance

    Args:
        name (str): Logger name (usually __name__)

    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(name)


# Security logging helpers
def log_security_event(event_type, user=None, ip=None, details=None):
    """
    Log security-related events

    Args:
        event_type (str): Type of security event
        user: User object or username
        ip (str): IP address
        details (dict): Additional details
    """
    security_logger = logging.getLogger('security')

    username = user.username if hasattr(user, 'username') else str(user) if user else 'anonymous'

    message = f"[{event_type}] User: {username}"
    if ip:
        message += f" | IP: {ip}"
    if details:
        message += f" | Details: {details}"

    security_logger.info(message)


def log_scan_event(scan_id, event_type, details=None):
    """
    Log scan-related events

    Args:
        scan_id: Scan ID
        event_type (str): Type of scan event
        details: Additional details
    """
    scan_logger = logging.getLogger('scans')

    message = f"[Scan #{scan_id}] {event_type}"
    if details:
        message += f" | {details}"

    scan_logger.info(message)

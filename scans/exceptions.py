from rest_framework.exceptions import APIException


class ScanBrokerUnavailable(Exception):
    """Raised when the scan cannot be queued due to broker/worker connectivity."""


class ScanQueueUnavailable(APIException):
    status_code = 503
    default_detail = 'Scan queue is temporarily unavailable. Please try again later.'
    default_code = 'scan_queue_unavailable'

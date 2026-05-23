from rest_framework.throttling import UserRateThrottle


class _PerUserThrottle(UserRateThrottle):
    """Base class that checks a per-user limit attribute before falling back to the global rate."""
    user_limit_attr = None  # Name of the User model field, e.g. 'scan_start_hourly_limit'

    def allow_request(self, request, view):
        if (
            self.user_limit_attr
            and request.user.is_authenticated
            and getattr(request.user, self.user_limit_attr, None) is not None
        ):
            self.rate = f"{getattr(request.user, self.user_limit_attr)}/hour"
            self.num_requests, self.duration = self.parse_rate(self.rate)
        return super().allow_request(request, view)


class ScanStartRateThrottle(_PerUserThrottle):
    scope = "scan_start"
    user_limit_attr = "scan_start_hourly_limit"


class ScanStopRateThrottle(_PerUserThrottle):
    scope = "scan_stop"
    user_limit_attr = "scan_stop_hourly_limit"


class ExportRateThrottle(_PerUserThrottle):
    scope = "export"
    user_limit_attr = "export_hourly_limit"

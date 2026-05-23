"""Scan audit logging helpers (v3.0).

Centralizes creation of users.audit_models.ScanAuditLog entries.
"""

from __future__ import annotations

from typing import Any, Optional

from django.conf import settings
from django.http import HttpRequest

from utils.error_handling import get_client_ip

from .audit_models import ScanAuditLog


def _normalize_ip(ip: Optional[str]) -> str:
    return ip or "127.0.0.1"


def _map_scan_type(scan_category_name: Optional[str], legacy_scan_type: Optional[str]) -> str:
    """Map Scan.scan_category/scan_type to ScanAuditLog.SCAN_TYPES."""
    if scan_category_name:
        name = str(scan_category_name).lower()
        if name in {"recon", "web", "api", "vuln", "mobile", "custom"}:
            return name

    legacy = (legacy_scan_type or "").lower()
    legacy_map = {
        "reconnaissance": "recon",
        "web_security": "web",
        "api_security": "api",
        "vulnerability": "vuln",
        "mobile": "mobile",
    }
    return legacy_map.get(legacy, "web")


def _extract_scan_metrics(scan) -> dict[str, Any]:
    """Best-effort extraction of metrics for ScanAuditLog fields."""
    vulnerabilities_found = int(getattr(scan, "vulnerabilities_found", 0) or 0)
    severity_counts = getattr(scan, "severity_counts", None) or {}

    severity_critical = int(severity_counts.get("critical", 0) or 0)
    severity_high = int(severity_counts.get("high", 0) or 0)
    severity_medium = int(severity_counts.get("medium", 0) or 0)
    severity_low = int(severity_counts.get("low", 0) or 0)

    duration_seconds: Optional[int] = None
    started_at = getattr(scan, "started_at", None)
    completed_at = getattr(scan, "completed_at", None)
    if started_at and completed_at:
        try:
            duration_seconds = max(0, int((completed_at - started_at).total_seconds()))
        except Exception:
            duration_seconds = None

    return {
        "vulnerabilities_found": vulnerabilities_found,
        "severity_critical": severity_critical,
        "severity_high": severity_high,
        "severity_medium": severity_medium,
        "severity_low": severity_low,
        "duration_seconds": duration_seconds,
    }


def _coerce_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    try:
        s = str(value).strip().lower()
    except Exception:
        return None
    if s in {"true", "1", "yes", "y", "on"}:
        return True
    if s in {"false", "0", "no", "n", "off"}:
        return False
    return None


def create_scan_audit_log(
    *,
    request: HttpRequest,
    user,
    action: str,
    target: str,
    scan=None,
    metadata: Optional[dict[str, Any]] = None,
    error_message: str = "",
) -> ScanAuditLog:
    ip = _normalize_ip(get_client_ip(request))
    user_agent = request.META.get("HTTP_USER_AGENT", "") or ""

    scan_category_name = None
    legacy_scan_type = None
    if scan is not None:
        scan_category_name = getattr(getattr(scan, "scan_category", None), "name", None)
        legacy_scan_type = getattr(scan, "scan_type", None)

    scan_type = _map_scan_type(scan_category_name, legacy_scan_type)

    metrics: dict[str, Any] = {}
    if scan is not None:
        metrics = _extract_scan_metrics(scan)

    merged_metadata: dict[str, Any] = dict(metadata or {})

    # Best-effort: capture scan consent evidence (per request) without logging full request bodies.
    try:
        request_data = getattr(request, "data", None)
        consent_raw = None
        if isinstance(request_data, dict):
            consent_raw = request_data.get("consent")
        consent_value = _coerce_bool(consent_raw)
        if consent_value is not None:
            merged_metadata.setdefault("consent", consent_value)
            merged_metadata.setdefault("consent_version", getattr(settings, "SCAN_CONSENT_VERSION", ""))
            merged_metadata.setdefault("consent_text", getattr(settings, "SCAN_CONSENT_TEXT", ""))
    except Exception:
        pass

    log = ScanAuditLog.objects.create(
        scan=scan,
        user=user,
        action=action,
        scan_type=scan_type,
        target=target,
        ip_address=ip,
        user_agent=user_agent,
        error_message=error_message or "",
        metadata=merged_metadata,
        **metrics,
    )
    return log


def create_scan_audit_log_system(
    *,
    scan,
    action: str,
    metadata: Optional[dict[str, Any]] = None,
    error_message: str = "",
    ip_address: str = "127.0.0.1",
    user_agent: str = "celery",
) -> ScanAuditLog:
    """Create ScanAuditLog for events emitted without an HttpRequest (Celery/tasks/admin).

    Uses scan.user and scan.target as the primary attribution.
    """
    scan_category_name = getattr(getattr(scan, "scan_category", None), "name", None)
    legacy_scan_type = getattr(scan, "scan_type", None)
    scan_type = _map_scan_type(scan_category_name, legacy_scan_type)

    metrics = _extract_scan_metrics(scan)

    return ScanAuditLog.objects.create(
        scan=scan,
        user=getattr(scan, "user", None),
        action=action,
        scan_type=scan_type,
        target=getattr(scan, "target", ""),
        ip_address=_normalize_ip(ip_address),
        user_agent=user_agent or "",
        error_message=error_message or "",
        metadata=metadata or {},
        **metrics,
    )

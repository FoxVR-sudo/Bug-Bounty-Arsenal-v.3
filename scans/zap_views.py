"""
scans/zap_views.py

API endpoints for OWASP ZAP scans (separate component).

Endpoints:
  POST /api/zap/scan/         — start a new ZAP scan
  GET  /api/zap/scan/<id>/    — get status + findings for a ZAP scan
  POST /api/zap/scan/<id>/cancel/  — cancel a running ZAP scan
"""

from __future__ import annotations

import logging

from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from scans.models import Scan
from scans.serializers import ScanDetailSerializer
from scans.throttles import ScanStartRateThrottle

logger = logging.getLogger(__name__)

# ── Helpers ────────────────────────────────────────────────────────────────────

_VALID_MODES = {"baseline", "full", "api"}


def _zap_enabled() -> bool:
    return bool(getattr(settings, "ZAP_ENABLED", False))


# ── Views ──────────────────────────────────────────────────────────────────────

@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([ScanStartRateThrottle])
def zap_scan_start(request):
    """
    Start an OWASP ZAP scan.

    POST /api/zap/scan/
    {
        "target":      "https://example.com",   // required
        "scan_mode":   "baseline",              // baseline | full | api  (default: baseline)
        "openapi_url": "https://example.com/openapi.json"  // only for mode=api
    }

    Returns:
        201 { scan_id, status, message }
        503 if ZAP is not enabled
        400 on validation error
    """
    if not _zap_enabled():
        return Response(
            {
                "error": (
                    "OWASP ZAP integration is not enabled. "
                    "Set ZAP_ENABLED=True and ZAP_API_KEY in your .env file, "
                    "and make sure Docker is installed on the server."
                )
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    target = str(request.data.get("target") or "").strip()
    if not target:
        return Response({"error": "target is required."}, status=status.HTTP_400_BAD_REQUEST)

    scan_mode = str(request.data.get("scan_mode") or "baseline").strip().lower()
    if scan_mode not in _VALID_MODES:
        return Response(
            {"error": f"scan_mode must be one of: {', '.join(sorted(_VALID_MODES))}."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    openapi_url = str(request.data.get("openapi_url") or "").strip()
    if scan_mode == "api" and not openapi_url:
        return Response(
            {"error": "openapi_url is required for scan_mode='api'."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Create Scan record — reuse existing model so findings appear in dashboard
    scan = Scan.objects.create(
        user=request.user,
        target=target,
        scan_type="web_security",
        status="pending",
        current_step="Queued for ZAP scan…",
        raw_results={
            "zap": True,
            "scan_mode": scan_mode,
            "openapi_url": openapi_url,
        },
    )

    # Dispatch Celery task
    try:
        from scans.tasks import run_zap_scan_task

        task = run_zap_scan_task.delay(
            scan_id=scan.id,
            target=target,
            scan_mode=scan_mode,
            openapi_url=openapi_url,
        )
        scan.celery_task_id = task.id
        scan.save(update_fields=["celery_task_id"])
    except Exception as exc:
        scan.status = "failed"
        scan.current_step = f"Failed to queue ZAP task: {exc}"
        scan.save(update_fields=["status", "current_step"])
        logger.exception("zap_scan_start: failed to queue task for scan %d", scan.id)
        return Response(
            {"error": "Failed to queue ZAP scan. Check that Celery is running."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    mode_labels = {
        "baseline": "Passive scan only (safe for production)",
        "full": "Active scan — SQL injection, XSS, etc. (test environments only)",
        "api": "OpenAPI/Swagger-driven scan",
    }

    return Response(
        {
            "scan_id": scan.id,
            "status": "pending",
            "scan_mode": scan_mode,
            "scan_mode_description": mode_labels[scan_mode],
            "target": target,
            "message": (
                "ZAP scan queued. Use GET /api/zap/scan/{scan_id}/ to track progress. "
                "Results will also appear in your scan dashboard."
            ),
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def zap_scan_status(request, scan_id: int):
    """
    Get status and findings for a ZAP scan.

    GET /api/zap/scan/<scan_id>/
    """
    try:
        scan = Scan.objects.get(id=scan_id, user=request.user)
    except Scan.DoesNotExist:
        return Response({"error": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)

    if not scan.raw_results.get("zap"):
        return Response(
            {"error": "This scan was not started by the ZAP component."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    serializer = ScanDetailSerializer(scan)
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def zap_scan_cancel(request, scan_id: int):
    """
    Cancel a running ZAP scan.

    POST /api/zap/scan/<scan_id>/cancel/
    """
    try:
        scan = Scan.objects.get(id=scan_id, user=request.user)
    except Scan.DoesNotExist:
        return Response({"error": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)

    if not scan.raw_results.get("zap"):
        return Response(
            {"error": "This scan was not started by the ZAP component."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if scan.status not in ("pending", "running"):
        return Response(
            {"message": f"Scan already {scan.status}."},
            status=status.HTTP_200_OK,
        )

    # Stop Docker container (best-effort)
    try:
        from scans.zap_service import _stop_zap_container
        _stop_zap_container(scan_id)
    except Exception:
        pass

    # Cancel Celery task
    if scan.celery_task_id:
        try:
            from config.celery import app as celery_app
            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        except Exception:
            pass

    scan.cancel_scan()
    return Response({"message": "ZAP scan cancelled."}, status=status.HTTP_200_OK)

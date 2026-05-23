"""
scans/mobile_views.py

API endpoint for mobile app security scanning (APK / IPA upload).

Endpoint:
  POST /api/mobile/scan/  — multipart form upload
  GET  /api/mobile/scan/<id>/  — scan status + findings
"""

from __future__ import annotations

import logging
import os
import uuid

from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes, permission_classes, throttle_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from scans.models import Scan
from scans.serializers import ScanDetailSerializer
from scans.throttles import ScanStartRateThrottle

logger = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────────────────────────

_ALLOWED_EXTENSIONS = {".apk", ".ipa"}
_ALLOWED_MIME_TYPES = {"application/octet-stream", "application/zip", "application/vnd.android.package-archive"}
_MAX_FILE_SIZE_MB = getattr(settings, "MOBILE_SCAN_MAX_FILE_SIZE_MB", 100)
_MAX_FILE_BYTES = _MAX_FILE_SIZE_MB * 1024 * 1024

# APK/IPA magic bytes (both are ZIP files → PK\x03\x04)
_ZIP_MAGIC = b"PK\x03\x04"


def _get_upload_dir() -> str:
    upload_dir = getattr(settings, "MOBILE_SCAN_UPLOAD_DIR", None) or os.path.join(
        settings.BASE_DIR, "tmp", "mobile_uploads"
    )
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir


def _detect_platform(filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    if ext == ".apk":
        return "android"
    if ext == ".ipa":
        return "ios"
    return ""


def _safe_filename(original: str) -> str:
    """Generate a UUID-based safe filename, preserving the extension."""
    ext = os.path.splitext(original.lower())[1]
    if ext not in _ALLOWED_EXTENSIONS:
        ext = ".bin"
    return f"{uuid.uuid4().hex}{ext}"


# ── Views ───────────────────────────────────────────────────────────────────

@api_view(["POST"])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
@throttle_classes([ScanStartRateThrottle])
def mobile_scan_start(request):
    """
    Start a mobile app security scan by uploading an APK or IPA file.

    POST /api/mobile/scan/
    Content-Type: multipart/form-data

    Fields:
      file      : APK or IPA file (required)
      app_name  : Optional human-readable app name

    Returns:
      201 { scan_id, status, platform, message }
      400 on validation error
    """
    uploaded_file = request.FILES.get("file")
    if not uploaded_file:
        return Response({"error": "No file uploaded. Use field name 'file'."}, status=status.HTTP_400_BAD_REQUEST)

    original_name = uploaded_file.name or "unknown"
    ext = os.path.splitext(original_name.lower())[1]

    # Validate extension
    if ext not in _ALLOWED_EXTENSIONS:
        return Response(
            {"error": f"Unsupported file type '{ext}'. Upload a .apk (Android) or .ipa (iOS) file."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Validate file size
    if uploaded_file.size > _MAX_FILE_BYTES:
        return Response(
            {"error": f"File too large. Maximum size is {_MAX_FILE_SIZE_MB} MB."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Validate magic bytes (APK and IPA are both ZIP)
    header = uploaded_file.read(4)
    uploaded_file.seek(0)
    if header != _ZIP_MAGIC:
        return Response(
            {"error": "Invalid file format. The file does not appear to be a valid APK or IPA."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    platform = _detect_platform(original_name)
    app_name = str(request.data.get("app_name") or os.path.splitext(original_name)[0])[:100]

    # Save file securely
    upload_dir = _get_upload_dir()
    safe_name = _safe_filename(original_name)
    file_path = os.path.join(upload_dir, safe_name)

    try:
        with open(file_path, "wb") as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)
    except OSError as exc:
        logger.error("mobile_scan_start: failed to save upload: %s", exc)
        return Response({"error": "Failed to save uploaded file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Create Scan record
    scan = Scan.objects.create(
        user=request.user,
        target=app_name,
        scan_type="mobile",
        status="pending",
        current_step="Queued for mobile scan…",
        raw_results={
            "mobile": True,
            "platform": platform,
            "original_filename": original_name,
            "upload_path": file_path,
        },
    )

    # Dispatch Celery task
    try:
        from scans.tasks import run_mobile_scan_task

        task = run_mobile_scan_task.delay(
            scan_id=scan.id,
            file_path=file_path,
            platform=platform,
            app_name=app_name,
        )
        scan.celery_task_id = task.id
        scan.save(update_fields=["celery_task_id"])
    except Exception as exc:
        scan.status = "failed"
        scan.current_step = f"Failed to queue task: {exc}"
        scan.save(update_fields=["status", "current_step"])
        logger.exception("mobile_scan_start: failed to queue task for scan %d", scan.id)
        # Clean up uploaded file
        try:
            os.remove(file_path)
        except OSError:
            pass
        return Response(
            {"error": "Failed to queue scan. Check that Celery is running."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    platform_label = "Android APK" if platform == "android" else "iOS IPA"
    return Response(
        {
            "scan_id": scan.id,
            "status": "pending",
            "platform": platform,
            "platform_label": platform_label,
            "app_name": app_name,
            "message": (
                f"{platform_label} scan queued. Use GET /api/mobile/scan/{scan.id}/ "
                "to track progress. Results appear in your scan dashboard."
            ),
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def mobile_scan_status(request, scan_id: int):
    """
    Get status and findings for a mobile scan.

    GET /api/mobile/scan/<scan_id>/
    """
    try:
        scan = Scan.objects.get(id=scan_id, user=request.user)
    except Scan.DoesNotExist:
        return Response({"error": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)

    if not scan.raw_results.get("mobile"):
        return Response(
            {"error": "This scan was not started by the mobile scanner."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    serializer = ScanDetailSerializer(scan)
    return Response(serializer.data)

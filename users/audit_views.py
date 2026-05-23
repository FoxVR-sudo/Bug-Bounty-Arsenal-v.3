import csv

from django.http import StreamingHttpResponse
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from .audit_models import ScanAuditLog
from .audit_serializers import ScanAuditLogSerializer


class _Echo:
    """An object that implements just the write method of the file-like interface."""

    def write(self, value):
        return value


class ScanAuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = ScanAuditLogSerializer

    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = {
        "action": ["exact"],
        "scan_type": ["exact"],
        "ip_address": ["exact"],
        "scan_id": ["exact"],
        "created_at": ["gte", "lte"],
    }
    search_fields = ["target", "user_agent", "error_message"]
    ordering_fields = ["created_at", "action", "scan_type", "vulnerabilities_found"]
    ordering = ["-created_at"]

    def get_queryset(self):
        user = self.request.user
        qs = ScanAuditLog.objects.all().select_related("user")
        if user.is_staff or getattr(user, "is_admin", False):
            return qs
        return qs.filter(user=user)

    @action(detail=False, methods=["get"], url_path="export")
    def export(self, request):
        # NOTE: Avoid using `?format=` because DRF reserves it for renderer negotiation.
        export_format = (request.query_params.get("export_format") or "csv").lower()

        try:
            limit = int(request.query_params.get("limit") or 10000)
        except (TypeError, ValueError):
            limit = 10000
        limit = max(1, min(limit, 50000))

        qs = self.filter_queryset(self.get_queryset()).order_by("-created_at")[:limit]

        if export_format in {"json", "jsonl"}:
            data = ScanAuditLogSerializer(qs, many=True).data
            return Response({"count": len(data), "results": data}, status=status.HTTP_200_OK)

        # CSV streaming by default
        pseudo_buffer = _Echo()
        writer = csv.writer(pseudo_buffer)

        header = [
            "id",
            "created_at",
            "user_email",
            "action",
            "scan_type",
            "target",
            "ip_address",
            "user_agent",
            "vulnerabilities_found",
            "severity_critical",
            "severity_high",
            "severity_medium",
            "severity_low",
            "duration_seconds",
            "error_message",
        ]

        def row_iter():
            yield writer.writerow(header)
            for log in qs.iterator():
                yield writer.writerow(
                    [
                        log.id,
                        timezone.localtime(log.created_at).isoformat(),
                        getattr(log.user, "email", ""),
                        log.action,
                        log.scan_type,
                        log.target,
                        log.ip_address,
                        log.user_agent,
                        log.vulnerabilities_found,
                        log.severity_critical,
                        log.severity_high,
                        log.severity_medium,
                        log.severity_low,
                        log.duration_seconds,
                        log.error_message,
                    ]
                )

        filename = f"scan_audit_export_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
        resp = StreamingHttpResponse(row_iter(), content_type="text/csv")
        resp["Content-Disposition"] = f'attachment; filename="{filename}"'
        return resp

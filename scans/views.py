import logging
import json

from django.db.models import Case, Q, When, IntegerField, Value
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes, throttle_classes
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .exceptions import ScanBrokerUnavailable, ScanQueueUnavailable
from .models import Scan, Vulnerability, AuditLog, ApiKey
from .serializers import (
    ScanSerializer,
    ScanDetailSerializer,
    AuditLogSerializer,
    ApiKeySerializer,
    VulnerabilitySerializer,
)
from .throttles import ScanStartRateThrottle, ScanStopRateThrottle
from users.scan_audit import create_scan_audit_log

_SEVERITY_ORDER = Case(
    When(severity='critical', then=Value(1)),
    When(severity='high', then=Value(2)),
    When(severity='medium', then=Value(3)),
    When(severity='low', then=Value(4)),
    When(severity='info', then=Value(5)),
    default=Value(6),
    output_field=IntegerField(),
)

logger = logging.getLogger(__name__)


class ScanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Scan CRUD operations
    """
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['scan_type', 'status']
    search_fields = ['target']
    ordering_fields = ['started_at', 'completed_at', 'vulnerabilities_found']
    ordering = ['-started_at']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return ScanDetailSerializer
        return ScanSerializer

    def get_queryset(self):
        # Users can only see their own scans
        # Admins can see all scans
        base_queryset = Scan.objects.select_related('user', 'scan_category')
        u = self.request.user
        if u.is_superuser or getattr(u, 'is_admin', False) or u.is_staff:
            return base_queryset
        return base_queryset.filter(user=u)

    def get_throttles(self):
        # Stricter throttles for scan start/stop actions
        if self.action == 'create':
            return [ScanStartRateThrottle()]
        if self.action == 'cancel':
            return [ScanStopRateThrottle()]
        return super().get_throttles()

    def perform_create(self, serializer):
        """Create scan and start async execution."""
        from django.conf import settings

        # Get requested detectors (support both 'detectors' and 'enabled_detectors' for compatibility)
        requested_detectors = self.request.data.get('detectors') or self.request.data.get('enabled_detectors', [])

        # Require at least one detector to be selected
        if not requested_detectors:
            from rest_framework.exceptions import ValidationError
            raise ValidationError(detail="Please select at least one detector to run the scan.")

        # Gate dangerous detectors behind email verification (when enabled)
        if bool(getattr(settings, 'DANGEROUS_TOOLS_REQUIRE_EMAIL_VERIFICATION', True)):
            from scans.category_models import DetectorConfig

            dangerous_selected = DetectorConfig.objects.filter(
                is_active=True,
                is_dangerous=True,
                name__in=list(requested_detectors or []),
            ).exists()
            if dangerous_selected and not bool(getattr(self.request.user, 'is_verified', False)):
                from rest_framework.exceptions import PermissionDenied
                raise PermissionDenied(detail='Email verification required to run dangerous scanners.')

        # Save the scan instance
        scan = serializer.save(user=self.request.user)

        # Save selected detectors to the scan model
        scan.selected_detectors = requested_detectors
        scan.save(update_fields=['selected_detectors'])

        # Audit log: scan created
        create_scan_audit_log(
            request=self.request,
            user=self.request.user,
            scan=scan,
            action='scan_created',
            target=scan.target,
            metadata={
                'source': 'api:scan-list',
                'detectors': requested_detectors,
            },
        )

        # No subscription usage accounting in free mode

        # Get scan configuration from request data (supports nested options)
        options = (
            self.request.data.get('options') if isinstance(self.request.data, dict) else None
        )
        if not isinstance(options, dict):
            options = {}

        scan_config = {
            'concurrency': options.get('concurrency', self.request.data.get('concurrency', 10)),
            'timeout': options.get('timeout', self.request.data.get('timeout', 15)),
            'per_host_rate': options.get('per_host_rate', self.request.data.get('per_host_rate', 1.0)),
            'allow_destructive': options.get('allow_destructive', self.request.data.get('allow_destructive', True)),
            'bypass_cloudflare': options.get('bypass_cloudflare', self.request.data.get('bypass_cloudflare', False)),
            'enable_forbidden_probe': options.get(
                'enable_forbidden_probe',
                self.request.data.get('enable_forbidden_probe', False),
            ),
            'scan_mode': options.get('scan_mode', self.request.data.get('scan_mode', 'normal')),
            'run_all_selected_detectors': options.get(
                'run_all_selected_detectors',
                self.request.data.get('run_all_selected_detectors', False),
            ),
            'enabled_detectors': requested_detectors,
            # Optional detector-specific options
            'nuclei_templates': options.get('nuclei_templates', self.request.data.get('nuclei_templates')),
            'nuclei_severity': options.get('nuclei_severity', self.request.data.get('nuclei_severity')),
            'cve_db_path': options.get('cve_db_path', self.request.data.get('cve_db_path')),
            'nmap_preset': options.get('nmap_preset', self.request.data.get('nmap_preset', 'service')),
            'nmap_custom': options.get('nmap_custom', self.request.data.get('nmap_custom', '')),
        }

        # Start async scan
        if getattr(settings, 'SCANS_AUTO_START', True):
            try:
                scan.start_async_scan(scan_config)
                create_scan_audit_log(
                    request=self.request,
                    user=self.request.user,
                    scan=scan,
                    action='scan_started',
                    target=scan.target,
                    metadata={
                        'source': 'api:scan-list',
                        'options': scan_config,
                        'detectors': requested_detectors,
                    },
                )
            except ScanBrokerUnavailable as exc:
                create_scan_audit_log(
                    request=self.request,
                    user=self.request.user,
                    scan=scan,
                    action='scan_failed',
                    target=scan.target,
                    metadata={'source': 'api:scan-list', 'reason': 'broker_unavailable'},
                    error_message=str(exc),
                )
                raise ScanQueueUnavailable()
            except Exception as exc:
                create_scan_audit_log(
                    request=self.request,
                    user=self.request.user,
                    scan=scan,
                    action='scan_failed',
                    target=scan.target,
                    metadata={'source': 'api:scan-list'},
                    error_message=str(exc),
                )
                raise

    @extend_schema(
        description="Cancel a running or pending scan",
        responses={200: {'description': 'Scan cancelled successfully'}}
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def cancel(self, request, pk=None):
        """Cancel a running or pending scan"""
        scan = self.get_object()

        # Idempotent: if already finished/stopped, treat as success.
        if scan.status not in ['running', 'pending']:
            return Response({'message': f'Scan already {scan.status}'}, status=status.HTTP_200_OK)

        # Cancel the scan
        if scan.cancel_scan():
            try:
                from users.scan_audit import create_scan_audit_log

                create_scan_audit_log(
                    request=request,
                    user=request.user,
                    scan=scan,
                    action='scan_cancelled',
                    target=scan.target,
                    metadata={'source': 'api:scan-cancel'},
                )
            except Exception:
                logger.exception("Failed writing audit log for cancelled scan %s", scan.id)
            return Response(
                {'message': 'Scan cancelled successfully'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Failed to cancel scan'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(
        description="Get the current status of a scan's Celery task",
        responses={200: {'description': 'Task status information'}}
    )
    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def task_status(self, request, pk=None):
        """Get the current status of the scan's Celery task"""
        scan = self.get_object()
        task_status = scan.get_task_status()

        if task_status is None:
            return Response(
                {'error': 'No task associated with this scan'},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response(task_status, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def stats(self, request):
        """Get scan statistics for the current user or all users for admins."""
        from datetime import timedelta

        from django.db.models import Count
        from django.utils import timezone

        queryset = self.get_queryset()

        now = timezone.now()
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start_of_month_window = now - timedelta(days=30)

        # Keep vulnerability aggregation aligned with the scan queryset.
        all_vulns = Vulnerability.objects.filter(scan__in=queryset)

        monthly_scans_qs = queryset.filter(created_at__gte=start_of_month_window)
        daily_scans_qs = queryset.filter(created_at__gte=start_of_day)

        monthly_vulns_qs = all_vulns.filter(created_at__gte=start_of_month_window)

        # Count by severity
        severity_counts = {
            'critical': all_vulns.filter(severity='critical').count(),
            'high': all_vulns.filter(severity='high').count(),
            'medium': all_vulns.filter(severity='medium').count(),
            'low': all_vulns.filter(severity='low').count(),
            'info': all_vulns.filter(severity='info').count(),
        }

        # Count by detector/type
        vuln_by_type = {}
        detector_counts = all_vulns.values('detector').annotate(count=Count('id'))
        for item in detector_counts:
            vuln_by_type[item['detector']] = item['count']

        completed_count = queryset.filter(status='completed').count()
        running_count = queryset.filter(status='running').count()
        failed_count = queryset.filter(status='failed').count()
        pending_count = queryset.filter(status='pending').count()

        return Response({
            # Existing keys (kept for backwards compatibility)
            'total_scans': queryset.count(),
            'completed': completed_count,
            'running': running_count,
            'failed': failed_count,
            'pending': pending_count,
            'total_vulnerabilities': all_vulns.count(),
            'severity': severity_counts,
            'vuln_by_type': vuln_by_type,

            # Frontend-friendly keys used by Profile / Dashboard widgets
            'daily_scans': daily_scans_qs.count(),
            'completed_today': queryset.filter(status='completed', completed_at__gte=start_of_day).count(),
            'running_scans': running_count,
            'queued_scans': pending_count,
            'monthly_scans': monthly_scans_qs.count(),
            'monthly_completed': monthly_scans_qs.filter(status='completed').count(),
            'monthly_vulnerabilities': monthly_vulns_qs.count(),
            'monthly_critical': monthly_vulns_qs.filter(severity='critical').count(),
        })

    # DEPRECATED: Replaced by export_scan_report_view custom URL endpoint
    # @action(detail=True, methods=['get'], url_path='export', url_name='export',
    #         renderer_classes=[])  # Disable DRF renderers, we return Django HttpResponse
    def _export_DEPRECATED(self, request, pk=None):
        """DEPRECATED - Export scan results in various formats (json, csv, pdf)"""
        from django.http import HttpResponse
        import csv
        import logging

        logger = logging.getLogger(__name__)
        logger.error(f">>> EXPORT ACTION CALLED: pk={pk}, query_params={request.query_params}, GET={request.GET}")

        scan = self.get_object()
        format_type = request.query_params.get('format', 'json').lower()
        logger.error(f">>> format_type={format_type}")

        # Get vulnerabilities
        vulnerabilities = scan.vulnerabilities.all()

        if format_type == 'json':
            # JSON export
            # Calculate duration
            duration_seconds = None
            if scan.started_at and scan.completed_at:
                duration_seconds = (scan.completed_at - scan.started_at).total_seconds()

            data = {
                'scan': {
                    'id': scan.id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'status': scan.status,
                    'started_at': scan.started_at.isoformat() if scan.started_at else None,
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'duration': f"{duration_seconds:.2f}s" if duration_seconds else None,
                    'vulnerabilities_found': scan.vulnerabilities_found,
                },
                'vulnerabilities': [
                    {
                        'title': v.title,
                        'description': v.description,
                        'severity': v.severity,
                        'detector': v.detector,
                        'url': v.url,
                        'payload': v.payload,
                        'evidence': v.evidence,
                        'status_code': v.status_code,
                    }
                    for v in vulnerabilities
                ]
            }
            response = HttpResponse(
                json.dumps(data, indent=2),
                content_type='application/json'
            )
            response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.json"'

        elif format_type == 'csv':
            # CSV export
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.csv"'

            writer = csv.writer(response)
            writer.writerow(['Title', 'Severity', 'Detector', 'URL', 'Description', 'Evidence'])

            for v in vulnerabilities:
                writer.writerow([
                    v.title,
                    v.severity,
                    v.detector,
                    v.url or '',
                    v.description or '',
                    v.evidence or ''
                ])

        elif format_type == 'pdf':
            # PDF export
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_CENTER
            from io import BytesIO

            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
            elements = []

            styles = getSampleStyleSheet()

            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1f2937'),
                spaceAfter=30,
                alignment=TA_CENTER
            )

            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#3b82f6'),
                spaceAfter=12,
                spaceBefore=12
            )

            # Title
            elements.append(Paragraph("Security Scan Report", title_style))
            elements.append(Spacer(1, 0.2 * inch))

            # Scan Info
            elements.append(Paragraph("Scan Information", heading_style))

            # Calculate duration for PDF
            duration_str = 'N/A'
            if scan.started_at and scan.completed_at:
                duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
                duration_str = f"{duration_seconds:.2f}s"

            scan_info_data = [
                ['Scan ID:', str(scan.id)],
                ['Target:', scan.target],
                [
                    'Scan Type:',
                    (
                        scan.get_scan_type_display()
                        if hasattr(scan, 'get_scan_type_display')
                        else scan.scan_type
                    ),
                ],
                ['Status:', scan.status.upper()],
                ['Started:', scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'],
                ['Completed:', scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A'],
                ['Duration:', duration_str],
                ['Vulnerabilities Found:', str(scan.vulnerabilities_found)],
            ]

            scan_info_table = Table(scan_info_data, colWidths=[2 * inch, 4.5 * inch])
            scan_info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(scan_info_table)
            elements.append(Spacer(1, 0.3 * inch))

            # Severity Summary
            if scan.severity_counts:
                elements.append(Paragraph("Severity Summary", heading_style))
                severity_data = [['Severity', 'Count']]
                severity_colors = {
                    'critical': colors.HexColor('#dc2626'),
                    'high': colors.HexColor('#ea580c'),
                    'medium': colors.HexColor('#f59e0b'),
                    'low': colors.HexColor('#3b82f6'),
                    'info': colors.HexColor('#6b7280')
                }

                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    count = scan.severity_counts.get(severity, 0)
                    if count > 0:
                        severity_data.append([severity.capitalize(), str(count)])

                if len(severity_data) > 1:
                    severity_table = Table(severity_data, colWidths=[3 * inch, 3.5 * inch])
                    severity_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 12),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ]))
                    elements.append(severity_table)
                    elements.append(Spacer(1, 0.3 * inch))

            # Vulnerabilities Details
            if vulnerabilities.exists():
                elements.append(Paragraph("Vulnerability Details", heading_style))
                elements.append(Spacer(1, 0.1 * inch))

                for idx, vuln in enumerate(vulnerabilities, 1):
                    # Vulnerability header
                    vuln_title = f"{idx}. {vuln.title} [{vuln.severity.upper()}]"
                    vuln_style = ParagraphStyle(
                        'VulnTitle',
                        parent=styles['Heading3'],
                        fontSize=12,
                        textColor=severity_colors.get(vuln.severity, colors.black),
                        spaceAfter=6
                    )
                    elements.append(Paragraph(vuln_title, vuln_style))

                    # Vulnerability details
                    vuln_details = [['Detector:', vuln.detector]]
                    if vuln.url:
                        url_value = vuln.url[:100] + '...' if len(vuln.url) > 100 else vuln.url
                    else:
                        url_value = 'N/A'
                    vuln_details.append(['URL:', url_value])

                    if vuln.description:
                        desc = vuln.description[:200] + '...' if len(vuln.description) > 200 else vuln.description
                        vuln_details.append(['Description:', desc])

                    if vuln.payload:
                        payload = vuln.payload[:150] + '...' if len(vuln.payload) > 150 else vuln.payload
                        vuln_details.append(['Payload:', payload])

                    if vuln.status_code:
                        vuln_details.append(['Status Code:', str(vuln.status_code)])

                    vuln_table = Table(vuln_details, colWidths=[1.5 * inch, 5 * inch])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9fafb')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ]))
                    elements.append(vuln_table)
                    elements.append(Spacer(1, 0.15 * inch))

                    # Page break every 3 vulnerabilities to avoid cramping
                    if idx % 3 == 0 and idx < vulnerabilities.count():
                        elements.append(PageBreak())
            else:
                elements.append(Paragraph("No vulnerabilities found.", styles['Normal']))

            # Build PDF
            doc.build(elements)
            pdf = buffer.getvalue()
            buffer.close()

            response = HttpResponse(pdf, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.pdf"'

        else:
            # Unsupported format
            return Response(
                {'error': f'Unsupported format: {format_type}. Use json, csv, or pdf.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return response

    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def vulnerabilities(self, request, pk=None):
        """Get vulnerabilities for this scan"""
        from .serializers import VulnerabilitySerializer
        from rest_framework.pagination import PageNumberPagination

        scan = get_object_or_404(self.get_queryset(), pk=pk)
        vulnerabilities = scan.vulnerabilities.annotate(
            severity_order=_SEVERITY_ORDER
        ).order_by('severity_order', '-cvss_score', '-confidence', '-created_at')

        severity = str(request.query_params.get('severity', '') or '').strip().lower()
        if severity:
            vulnerabilities = vulnerabilities.filter(severity=severity)

        detector = str(request.query_params.get('detector', '') or '').strip()
        if detector:
            vulnerabilities = vulnerabilities.filter(detector=detector)

        verified_only = str(request.query_params.get('verified_only', '') or '').strip().lower()
        if verified_only in ('1', 'true', 'yes'):
            vulnerabilities = vulnerabilities.filter(is_verified=True)
        else:
            is_verified = str(request.query_params.get('is_verified', '') or '').strip().lower()
            if is_verified in ('1', 'true', 'yes'):
                vulnerabilities = vulnerabilities.filter(is_verified=True)
            elif is_verified in ('0', 'false', 'no'):
                vulnerabilities = vulnerabilities.filter(is_verified=False)

        confidence_min = request.query_params.get('confidence_min')
        if confidence_min is not None:
            try:
                vulnerabilities = vulnerabilities.filter(confidence__gte=int(confidence_min))
            except (TypeError, ValueError):
                pass

        search = str(request.query_params.get('search', '') or '').strip()
        if search:
            vulnerabilities = vulnerabilities.filter(
                Q(title__icontains=search)
                | Q(description__icontains=search)
                | Q(detector__icontains=search)
                | Q(url__icontains=search)
                | Q(evidence__icontains=search)
                | Q(payload__icontains=search)
                | Q(notes__icontains=search)
            )

        # Apply pagination
        paginator = PageNumberPagination()
        paginator.page_size = 20
        result_page = paginator.paginate_queryset(vulnerabilities, request)

        serializer = VulnerabilitySerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)


@extend_schema(
    summary="Get scan status",
    description="Get all scans for the current user with their status",
    tags=["Scans"]
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_status_view(request):
    """Get all scans for current user"""
    scans = Scan.objects.filter(user=request.user).order_by('-started_at')
    serializer = ScanSerializer(scans, many=True)
    return Response(serializer.data)


@extend_schema(
    summary="Start new scan",
    description="Start a new vulnerability scan with the provided configuration",
    tags=["Scans"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string', 'description': 'Target URL or domain'},
                'scan_type': {'type': 'string', 'enum': ['quick', 'standard', 'deep', 'brutal']},
                'scope_file': {'type': 'string', 'description': 'Optional scope file content'},
                'concurrency': {'type': 'integer', 'default': 10},
                'timeout': {'type': 'integer', 'default': 15},
                'scan_mode': {'type': 'string', 'enum': ['normal', 'stealth', 'aggressive']}
            },
            'required': ['target', 'scan_type']
        }
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([ScanStartRateThrottle])
def scan_start_view(request):
    """Start a new scan"""
    from django.conf import settings

    serializer = ScanSerializer(data=request.data, context={'request': request})

    if not serializer.is_valid():
        return Response(
            {'errors': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Get requested detectors (support both 'detectors' and 'enabled_detectors')
    requested_detectors = (
        request.data.get('detectors')
        or request.data.get('enabled_detectors')
        or []
    )

    if not requested_detectors:
        return Response({'error': 'Please select at least one detector to run the scan.'},
                        status=status.HTTP_400_BAD_REQUEST)

    # Gate dangerous detectors behind email verification (when enabled)
    if bool(getattr(settings, 'DANGEROUS_TOOLS_REQUIRE_EMAIL_VERIFICATION', True)):
        from scans.category_models import DetectorConfig

        dangerous_selected = DetectorConfig.objects.filter(
            is_active=True,
            is_dangerous=True,
            name__in=list(requested_detectors or []),
        ).exists()
        if dangerous_selected and not bool(getattr(request.user, 'is_verified', False)):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied(detail='Email verification required to run dangerous scanners.')

    # Create scan - let serializer handle raw_results default
    scan = serializer.save(user=request.user)
    scan.selected_detectors = requested_detectors
    scan.save(update_fields=['selected_detectors'])

    # Audit log: scan created
    create_scan_audit_log(
        request=request,
        user=request.user,
        scan=scan,
        action='scan_created',
        target=scan.target,
        metadata={
            'source': 'api:scan-start',
            'detectors': requested_detectors,
        },
    )

    # Support passing scan options either at top-level or under an "options" object.
    options = request.data.get('options') if isinstance(request.data, dict) else None
    if not isinstance(options, dict):
        options = {}

    # No subscription usage accounting in free mode

    # Get scan configuration
    scan_config = {
        'concurrency': options.get('concurrency', request.data.get('concurrency', 10)),
        'timeout': options.get('timeout', request.data.get('timeout', 15)),
        'per_host_rate': options.get('per_host_rate', request.data.get('per_host_rate', 1.0)),
        'allow_destructive': options.get('allow_destructive', request.data.get('allow_destructive', True)),
        'bypass_cloudflare': options.get('bypass_cloudflare', request.data.get('bypass_cloudflare', False)),
        'enable_forbidden_probe': options.get(
            'enable_forbidden_probe',
            request.data.get('enable_forbidden_probe', False),
        ),
        'scan_mode': options.get('scan_mode', request.data.get('scan_mode', 'normal')),
        'run_all_selected_detectors': options.get(
            'run_all_selected_detectors',
            request.data.get('run_all_selected_detectors', False),
        ),
        'enabled_detectors': requested_detectors,
        # Optional detector-specific options
        'nuclei_templates': options.get('nuclei_templates', request.data.get('nuclei_templates')),
        'nuclei_severity': options.get('nuclei_severity', request.data.get('nuclei_severity')),
        'cve_db_path': options.get('cve_db_path', request.data.get('cve_db_path')),
    }

    if getattr(settings, 'SCANS_AUTO_START', True):
        try:
            scan.start_async_scan(scan_config)
            create_scan_audit_log(
                request=request,
                user=request.user,
                scan=scan,
                action='scan_started',
                target=scan.target,
                metadata={
                    'source': 'api:scan-start',
                    'options': scan_config,
                },
            )
        except ScanBrokerUnavailable as exc:
            create_scan_audit_log(
                request=request,
                user=request.user,
                scan=scan,
                action='scan_failed',
                target=scan.target,
                metadata={'source': 'api:scan-start', 'reason': 'broker_unavailable'},
                error_message=str(exc),
            )
            raise ScanQueueUnavailable()
        except Exception as exc:
            create_scan_audit_log(
                request=request,
                user=request.user,
                scan=scan,
                action='scan_failed',
                target=scan.target,
                metadata={'source': 'api:scan-start'},
                error_message=str(exc),
            )
            raise

    return Response(
        ScanDetailSerializer(scan).data,
        status=status.HTTP_201_CREATED
    )


@extend_schema(
    summary="Stop running scan",
    description="Cancel a running or pending scan",
    tags=["Scans"]
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([ScanStopRateThrottle])
def scan_stop_view(request, scan_id):
    """Stop a running scan"""
    try:
        scan = Scan.objects.get(id=scan_id, user=request.user)
    except Scan.DoesNotExist:
        return Response(
            {'error': 'Scan not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    if scan.status not in ['running', 'pending']:
        return Response({'message': f'Scan already {scan.status}'}, status=status.HTTP_200_OK)

    # Cancel the scan
    if scan.cancel_scan():
        try:
            from users.scan_audit import create_scan_audit_log

            create_scan_audit_log(
                request=request,
                user=request.user,
                scan=scan,
                action='scan_cancelled',
                target=scan.target,
                metadata={'source': 'api:scan-stop'},
            )
        except Exception:
            logger.exception("Failed writing audit log for cancelled scan %s", scan.id)
        return Response(
            {'message': 'Scan cancelled successfully'},
            status=status.HTTP_200_OK
        )
    else:
        return Response(
            {'error': 'Failed to cancel scan'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Validate scope file",
    description="Validate the format and content of a scope file",
    tags=["Scans"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'scope_content': {'type': 'string', 'description': 'Content of the scope file'}
            },
            'required': ['scope_content']
        }
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def validate_scope_view(request):
    """Validate scope file content"""
    scope_content = request.data.get('scope_content', '')

    if not scope_content:
        return Response(
            {'error': 'scope_content is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Basic validation
    lines = scope_content.strip().split('\n')
    valid_lines = []
    invalid_lines = []

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Check if line is valid URL or domain
        if '://' in line or '.' in line:
            valid_lines.append(line)
        else:
            invalid_lines.append({'line': i, 'content': line, 'error': 'Invalid URL or domain format'})

    if len(invalid_lines) == 0:
        message = f'Found {len(valid_lines)} valid targets'
    else:
        message = f'Found {len(invalid_lines)} invalid lines'

    return Response(
        {
            'valid': len(invalid_lines) == 0,
            'total_lines': len(lines),
            'valid_targets': len(valid_lines),
            'invalid_lines': invalid_lines,
            'message': message,
        }
    )


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for AuditLog (read-only)
    """
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['event_type', 'user']
    search_fields = ['description', 'event_type']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        # Users can only see their own audit logs
        # Admins can see all audit logs
        u = self.request.user
        if u.is_superuser or getattr(u, 'is_admin', False) or u.is_staff:
            return AuditLog.objects.all()
        return AuditLog.objects.filter(user=self.request.user)


class VulnerabilityViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Vulnerability findings.

    Supports filtering by:
    - severity          (critical/high/medium/low/info)
    - is_verified       (true/false) — show only verified/unverified findings
    - verified_only     (true) — alias for is_verified=true (convenience param)
    - detector          (exact detector name)
    - confidence_min    (integer 0-100) — minimum confidence threshold
    - scan              (scan id)

    Ordering: severity, confidence, cvss_score, created_at
    """
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['severity', 'is_verified', 'detector', 'scan']
    search_fields = ['title', 'description', 'url', 'evidence']
    ordering_fields = ['severity_order', 'severity', 'confidence', 'cvss_score', 'created_at']
    ordering = ['severity_order', '-cvss_score', '-confidence', '-created_at']
    http_method_names = ['get', 'patch', 'head', 'options']  # no create/delete via this endpoint

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or getattr(user, 'is_admin', False) or user.is_staff:
            qs = Vulnerability.objects.all()
        else:
            qs = Vulnerability.objects.filter(scan__user=user)

        # verified_only convenience alias
        if self.request.query_params.get('verified_only', '').lower() in ('1', 'true', 'yes'):
            qs = qs.filter(is_verified=True)

        # confidence_min filter
        confidence_min = self.request.query_params.get('confidence_min')
        if confidence_min is not None:
            try:
                qs = qs.filter(confidence__gte=int(confidence_min))
            except (ValueError, TypeError):
                pass

        return qs.select_related('scan').annotate(severity_order=_SEVERITY_ORDER)

    @extend_schema(
        description="Mark a vulnerability as verified by the user",
        responses={200: VulnerabilitySerializer},
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def verify(self, request, pk=None):
        """Toggle the is_verified status of a finding."""
        vuln = self.get_object()
        vuln.is_verified = not vuln.is_verified
        vuln.save(update_fields=['is_verified', 'updated_at'])
        return Response(self.get_serializer(vuln).data)


class ApiKeyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for ApiKey CRUD operations
    """
    serializer_class = ApiKeySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['is_active']
    ordering_fields = ['created_at', 'last_used_at']
    ordering = ['-created_at']

    def get_queryset(self):
        # Users can only see their own API keys
        # Admins can see all API keys
        u = self.request.user
        if u.is_superuser or getattr(u, 'is_admin', False) or u.is_staff:
            return ApiKey.objects.all()
        return ApiKey.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Set the user from request
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def revoke(self, request, pk=None):
        """Revoke (deactivate) an API key"""
        api_key = self.get_object()
        api_key.is_active = False
        api_key.save()
        return Response({'message': 'API key revoked successfully'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def regenerate(self, request, pk=None):
        """Regenerate an API key"""
        api_key = self.get_object()
        api_key.regenerate_key()
        serializer = self.get_serializer(api_key)
        return Response(serializer.data)


# Export views
@extend_schema(
    summary="Export scan report",
    description="Export scan report in specified format (html, pdf, json, csv)",
    tags=["Scans"]
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def export_scan_report_view(request, scan_id):
    """Export scan report in specified format"""
    from django.http import FileResponse
    from scans.exporters import export_scan_report
    import logging

    logger = logging.getLogger(__name__)
    logger.error(f"🎯 EXPORT VIEW CALLED! scan_id={scan_id}, format={request.query_params.get('format')}")

    # Get scan
    try:
        scan = Scan.objects.get(id=scan_id)
        logger.error(f"✅ Scan found: {scan.id}, status={scan.status}")
    except Scan.DoesNotExist:
        return Response(
            {'error': 'Scan not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    # Check permissions
    if not (request.user == scan.user or request.user.is_staff):
        return Response(
            {'error': 'Permission denied'},
            status=status.HTTP_403_FORBIDDEN
        )

    # Check if scan is completed
    if scan.status != 'completed':
        return Response(
            {'error': 'Scan is not completed yet'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Get format
    export_format = request.query_params.get('format', 'html').lower()
    if export_format not in ['html', 'pdf', 'json', 'csv']:
        return Response(
            {'error': 'Invalid format. Must be one of: html, pdf, json, csv'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Generate report
        file_path = export_scan_report(scan, export_format)

        # Update storage size
        scan.update_storage_size()

        # Determine content type
        content_types = {
            'html': 'text/html',
            'pdf': 'application/pdf',
            'json': 'application/json',
            'csv': 'text/csv',
        }

        # Return file
        file_name = f'scan_{scan.id}_report.{export_format}'
        response = FileResponse(
            open(file_path, 'rb'),
            content_type=content_types[export_format]
        )
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        return response

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Export error: {e}")

        return Response(
            {'error': f'Failed to generate report: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Export all formats as ZIP",
    description="Export scan report in all formats as a ZIP archive",
    tags=["Scans"]
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def export_all_formats_view(request, scan_id):
    """Export all report formats as ZIP"""
    from django.http import HttpResponse
    from scans.exporters import export_all_formats
    import zipfile
    import io
    import os

    # Get scan
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response(
            {'error': 'Scan not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    # Check permissions
    if not (request.user == scan.user or request.user.is_staff):
        return Response(
            {'error': 'Permission denied'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        # Generate all formats
        files = export_all_formats(scan)

        # Create ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for fmt, file_path in files.items():
                if os.path.exists(file_path):
                    arcname = f'scan_{scan.id}_report.{fmt}'
                    zip_file.write(file_path, arcname)

        # Update storage size
        scan.update_storage_size()

        # Return ZIP
        zip_buffer.seek(0)
        response = HttpResponse(zip_buffer.read(), content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename="scan_{scan.id}_all_reports.zip"'
        return response

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Export all error: {e}")

        return Response(
            {'error': f'Failed to generate reports: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

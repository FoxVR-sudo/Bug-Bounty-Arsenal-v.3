"""Simple export views - no query params, no conflicts."""

from django.conf import settings
from django.db.models import Case, When, IntegerField, Value
from django.http import HttpResponse, StreamingHttpResponse
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
import json
import csv
from io import BytesIO

from .models import Scan
from .throttles import ExportRateThrottle

_SEVERITY_ORDER = Case(
    When(severity='critical', then=Value(1)),
    When(severity='high', then=Value(2)),
    When(severity='medium', then=Value(3)),
    When(severity='low', then=Value(4)),
    When(severity='info', then=Value(5)),
    default=Value(6),
    output_field=IntegerField(),
)


def _get_scan_for_export(request, scan_id: int) -> Scan:
    if request.user.is_staff:
        return Scan.objects.get(id=scan_id)
    return Scan.objects.get(id=scan_id, user=request.user)


def _export_limits() -> tuple[int, int, int]:
    """Return (pdf_max, json_max, csv_max) vulnerability limits."""
    pdf_max = int(getattr(settings, 'EXPORT_MAX_VULNERABILITIES_PDF', 250) or 250)
    json_max = int(getattr(settings, 'EXPORT_MAX_VULNERABILITIES_JSON', 5000) or 5000)
    csv_max = int(getattr(settings, 'EXPORT_MAX_VULNERABILITIES_CSV', 10000) or 10000)
    return pdf_max, json_max, csv_max


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([ExportRateThrottle])
def export_pdf_view(request, scan_id):
    """Export scan as PDF"""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER

    try:
        scan = _get_scan_for_export(request, scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

    vulnerabilities = scan.vulnerabilities.annotate(
        severity_order=_SEVERITY_ORDER
    ).order_by('severity_order', '-cvss_score', '-confidence', '-created_at')
    pdf_max, _, _ = _export_limits()
    vuln_count = vulnerabilities.count()
    if vuln_count > pdf_max:
        return Response(
            {
                'error': 'Export too large',
                'detail': f'PDF export supports up to {pdf_max} findings; this scan has {vuln_count}.',
            },
            status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
    elements = []
    styles = getSampleStyleSheet()

    # Shared paragraph styles for table cells (Paragraph objects wrap text; plain strings do not)
    cell_label_style = ParagraphStyle(
        'CellLabel', parent=styles['Normal'], fontSize=10, leading=13, fontName='Helvetica-Bold'
    )
    cell_body_style = ParagraphStyle(
        'CellBody', parent=styles['Normal'], fontSize=10, leading=13
    )
    cell_label_sm = ParagraphStyle(
        'CellLabelSm', parent=styles['Normal'], fontSize=9, leading=12, fontName='Helvetica-Bold'
    )
    cell_body_sm = ParagraphStyle(
        'CellBodySm', parent=styles['Normal'], fontSize=9, leading=12
    )

    def _p(text, style):
        """Wrap text in a Paragraph for proper word-wrapping in table cells."""
        safe = str(text or 'N/A').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        return Paragraph(safe, style)

    # Title
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24,
                                 textColor=colors.HexColor('#1f2937'), spaceAfter=30, alignment=TA_CENTER)
    elements.append(Paragraph("Security Scan Report", title_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Scan Info
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14,
                                   textColor=colors.HexColor('#3b82f6'), spaceAfter=12, spaceBefore=12)
    elements.append(Paragraph("Scan Information", heading_style))

    duration_str = 'N/A'
    if scan.started_at and scan.completed_at:
        duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
        duration_str = f"{duration_seconds:.2f}s"

    scan_info_data = [
        [_p('Scan ID:', cell_label_style), _p(str(scan.id), cell_body_style)],
        [_p('Target:', cell_label_style), _p(scan.target, cell_body_style)],
        [_p('Status:', cell_label_style), _p(scan.status.upper(), cell_body_style)],
        [_p('Started:', cell_label_style),
         _p(scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A', cell_body_style)],
        [_p('Completed:', cell_label_style),
         _p(scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A', cell_body_style)],
        [_p('Duration:', cell_label_style), _p(duration_str, cell_body_style)],
        [_p('Vulnerabilities Found:', cell_label_style), _p(str(scan.vulnerabilities_found), cell_body_style)],
    ]

    scan_info_table = Table(scan_info_data, colWidths=[2 * inch, 4.5 * inch])
    scan_info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(scan_info_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Vulnerabilities
    if vulnerabilities.exists():
        elements.append(Paragraph("Vulnerability Details", heading_style))
        elements.append(Spacer(1, 0.1 * inch))

        severity_colors = {
            'critical': colors.HexColor('#dc2626'),
            'high': colors.HexColor('#ea580c'),
            'medium': colors.HexColor('#f59e0b'),
            'low': colors.HexColor('#3b82f6'),
            'info': colors.HexColor('#6b7280')
        }

        for idx, vuln in enumerate(vulnerabilities, 1):
            vuln_title = f"{idx}. {vuln.title} [{vuln.severity.upper()}]"
            vuln_style = ParagraphStyle(f'VulnTitle{idx}', parent=styles['Heading3'], fontSize=12,
                                        textColor=severity_colors.get(vuln.severity, colors.black), spaceAfter=6)
            elements.append(Paragraph(vuln_title, vuln_style))

            vuln_details = [
                [_p('Detector:', cell_label_sm), _p(vuln.detector, cell_body_sm)],
                [_p('URL:', cell_label_sm), _p(vuln.url or 'N/A', cell_body_sm)],
            ]

            if vuln.description:
                vuln_details.append([_p('Description:', cell_label_sm), _p(vuln.description, cell_body_sm)])

            if vuln.payload:
                vuln_details.append([_p('Payload:', cell_label_sm), _p(vuln.payload, cell_body_sm)])

            if vuln.evidence:
                vuln_details.append([_p('Evidence:', cell_label_sm), _p(vuln.evidence, cell_body_sm)])

            vuln_table = Table(vuln_details, colWidths=[1.5 * inch, 5 * inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9fafb')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.15 * inch))

            if idx % 3 == 0 and idx < vuln_count:
                elements.append(PageBreak())
    else:
        elements.append(Paragraph("No vulnerabilities found.", styles['Normal']))

    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()

    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.pdf"'
    return response


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([ExportRateThrottle])
def export_json_view(request, scan_id):
    """Export scan as JSON"""
    try:
        scan = _get_scan_for_export(request, scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

    vulnerabilities = scan.vulnerabilities.annotate(
        severity_order=_SEVERITY_ORDER
    ).order_by('severity_order', '-cvss_score', '-confidence', '-created_at')
    _, json_max, _ = _export_limits()
    vuln_count = vulnerabilities.count()
    if vuln_count > json_max:
        return Response(
            {
                'error': 'Export too large',
                'detail': f'JSON export supports up to {json_max} findings; this scan has {vuln_count}.',
            },
            status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )

    duration_seconds = None
    if scan.started_at and scan.completed_at:
        duration_seconds = (scan.completed_at - scan.started_at).total_seconds()

    scan_payload = {
        'id': scan.id,
        'target': scan.target,
        'scan_type': scan.scan_type,
        'status': scan.status,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'duration': f"{duration_seconds:.2f}s" if duration_seconds else None,
        'vulnerabilities_found': scan.vulnerabilities_found,
    }

    def stream_json():
        yield '{\n'
        yield '  "scan": '
        yield json.dumps(scan_payload, indent=2)
        yield ',\n  "vulnerabilities": [\n'

        first = True
        for v in vulnerabilities.iterator(chunk_size=500):
            item = {
                'title': v.title,
                'description': v.description,
                'severity': v.severity,
                'detector': v.detector,
                'url': v.url,
                'payload': v.payload,
                'evidence': v.evidence,
                'status_code': v.status_code,
            }
            if not first:
                yield ',\n'
            first = False
            yield json.dumps(item, ensure_ascii=False)

        yield '\n  ]\n}\n'

    response = StreamingHttpResponse(stream_json(), content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.json"'
    return response


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([ExportRateThrottle])
def export_csv_view(request, scan_id):
    """Export scan as CSV"""
    try:
        scan = _get_scan_for_export(request, scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

    vulnerabilities = scan.vulnerabilities.annotate(
        severity_order=_SEVERITY_ORDER
    ).order_by('severity_order', '-cvss_score', '-confidence', '-created_at')
    _, _, csv_max = _export_limits()
    vuln_count = vulnerabilities.count()
    if vuln_count > csv_max:
        return Response(
            {
                'error': 'Export too large',
                'detail': f'CSV export supports up to {csv_max} findings; this scan has {vuln_count}.',
            },
            status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )

    class _Echo:
        def write(self, value):
            return value

    def stream_csv():
        pseudo_buffer = _Echo()
        writer = csv.writer(pseudo_buffer)
        yield writer.writerow(['Title', 'Severity', 'Detector', 'URL', 'Description', 'Evidence'])
        for v in vulnerabilities.iterator(chunk_size=1000):
            yield writer.writerow([
                v.title,
                v.severity,
                v.detector,
                v.url or '',
                v.description or '',
                v.evidence or '',
            ])

    response = StreamingHttpResponse(stream_csv(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.csv"'
    return response

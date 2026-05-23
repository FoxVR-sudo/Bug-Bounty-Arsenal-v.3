"""
Report Export System
Handles generation of reports in multiple formats: HTML, PDF, JSON, CSV
"""

import os
import json
import csv
from typing import Dict, List, Any
from django.conf import settings
from django.template.loader import render_to_string


class ReportExporter:
    """Base class for report exporters"""

    def __init__(self, scan):
        self.scan = scan
        self.report_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
        os.makedirs(self.report_dir, exist_ok=True)

    def get_scan_data(self) -> Dict[str, Any]:
        """Prepare scan data for export"""
        return {
            'scan_id': self.scan.id,
            'target': self.scan.target,
            'scan_type': self.scan.get_scan_type_display(),
            'status': self.scan.status,
            'started_at': self.scan.started_at.isoformat() if self.scan.started_at else None,
            'completed_at': self.scan.completed_at.isoformat() if self.scan.completed_at else None,
            'duration': self._calculate_duration(),
            'vulnerabilities_found': self.scan.vulnerabilities_found,
            'severity_counts': self.scan.severity_counts,
            'vulnerabilities': self._format_vulnerabilities(),
            'statistics': self._get_statistics(),
            'user': {
                'email': self.scan.user.email,
                'tier': self._get_user_tier(),
            },
            'detectors_used': self._get_detectors_used(),
        }

    def _calculate_duration(self) -> str:
        """Calculate scan duration"""
        if not self.scan.started_at or not self.scan.completed_at:
            return 'N/A'

        delta = self.scan.completed_at - self.scan.started_at
        minutes = int(delta.total_seconds() / 60)
        seconds = int(delta.total_seconds() % 60)
        return f"{minutes}m {seconds}s"

    def _format_vulnerabilities(self) -> List[Dict]:
        """Format vulnerabilities from raw_results"""
        vulnerabilities = self.scan.raw_results.get('vulnerabilities', [])

        formatted = []
        for idx, vuln in enumerate(vulnerabilities, 1):
            formatted.append({
                'id': vuln.get('id', f'VULN-{idx:03d}'),
                'title': vuln.get('title', 'Unknown Vulnerability'),
                'severity': vuln.get('severity', 'info').upper(),
                'cvss': vuln.get('cvss', 0.0),
                'category': vuln.get('category', 'Other'),
                'url': vuln.get('url', self.scan.target),
                'description': vuln.get('description', 'No description available'),
                'payload': vuln.get('payload', ''),
                'evidence': vuln.get('evidence', ''),
                'remediation': vuln.get('remediation', 'No remediation steps provided'),
                'references': vuln.get('references', []),
                'detector': vuln.get('detector', 'unknown'),
            })

        return formatted

    def _get_statistics(self) -> Dict:
        """Get scan statistics"""
        severity_counts = self.scan.severity_counts or {}
        return {
            'total_vulnerabilities': self.scan.vulnerabilities_found,
            'critical': severity_counts.get('critical', 0),
            'high': severity_counts.get('high', 0),
            'medium': severity_counts.get('medium', 0),
            'low': severity_counts.get('low', 0),
            'info': severity_counts.get('info', 0),
        }

    def _get_user_tier(self) -> str:
        """Get user subscription tier"""
        try:
            return self.scan.user.subscription.plan.name
        except Exception:
            return 'FREE'

    def _get_detectors_used(self) -> Dict:
        """Get list of detectors used in scan"""
        # This would come from scan configuration
        return {
            'active': self.scan.raw_results.get('detectors', {}).get('active', []),
            'passive': self.scan.raw_results.get('detectors', {}).get('passive', []),
        }


class HTMLReportExporter(ReportExporter):
    """Export scan results as HTML"""

    def export(self) -> str:
        """Generate HTML report"""
        data = self.get_scan_data()
        html_content = render_to_string('reports/scan_report.html', {'scan': data})

        file_path = os.path.join(self.report_dir, f'scan_{self.scan.id}.html')
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return file_path


class PDFReportExporter(ReportExporter):
    """Export scan results as PDF"""

    def export(self) -> str:
        """Generate PDF report from HTML"""
        # First generate HTML
        html_exporter = HTMLReportExporter(self.scan)
        html_file = html_exporter.export()

        pdf_file = os.path.join(self.report_dir, f'scan_{self.scan.id}.pdf')

        try:
            # Try using WeasyPrint
            from weasyprint import HTML
            HTML(filename=html_file).write_pdf(pdf_file)
        except ImportError:
            # Fallback: Use ReportLab for basic PDF
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

            doc = SimpleDocTemplate(pdf_file, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()

            data = self.get_scan_data()

            # Title
            title = Paragraph(f"Security Scan Report - {data['target']}", styles['Title'])
            elements.append(title)
            elements.append(Spacer(1, 12))

            # Summary table
            summary_data = [
                ['Scan ID', data['scan_id']],
                ['Target', data['target']],
                ['Started', data['started_at']],
                ['Duration', data['duration']],
                ['Vulnerabilities', data['vulnerabilities_found']],
            ]

            summary_table = Table(summary_data, colWidths=[150, 350])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 20))

            # Vulnerabilities
            if data['vulnerabilities']:
                vuln_title = Paragraph("Vulnerabilities Found", styles['Heading2'])
                elements.append(vuln_title)
                elements.append(Spacer(1, 12))

                for vuln in data['vulnerabilities']:
                    vuln_text = f"<b>[{vuln['severity']}]</b> {vuln['title']}<br/>{vuln['url']}"
                    elements.append(Paragraph(vuln_text, styles['Normal']))
                    elements.append(Spacer(1, 8))

            doc.build(elements)

        return pdf_file


class JSONReportExporter(ReportExporter):
    """Export scan results as JSON"""

    def export(self) -> str:
        """Generate JSON report"""
        data = self.get_scan_data()

        file_path = os.path.join(self.report_dir, f'scan_{self.scan.id}.json')
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return file_path


class CSVReportExporter(ReportExporter):
    """Export scan results as CSV"""

    def export(self) -> str:
        """Generate CSV report"""
        data = self.get_scan_data()

        file_path = os.path.join(self.report_dir, f'scan_{self.scan.id}.csv')

        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(['ID', 'Title', 'Severity', 'CVSS', 'Category', 'URL', 'Description', 'Remediation'])

            # Vulnerabilities
            for vuln in data['vulnerabilities']:
                writer.writerow([
                    vuln['id'],
                    vuln['title'],
                    vuln['severity'],
                    vuln['cvss'],
                    vuln['category'],
                    vuln['url'],
                    vuln['description'][:200],  # Truncate long descriptions
                    vuln['remediation'][:200],
                ])

        return file_path


def export_scan_report(scan, format='html') -> str:
    """
    Export scan report in the specified format

    Args:
        scan: Scan model instance
        format: Export format ('html', 'pdf', 'json', 'csv')

    Returns:
        File path to generated report
    """
    exporters = {
        'html': HTMLReportExporter,
        'pdf': PDFReportExporter,
        'json': JSONReportExporter,
        'csv': CSVReportExporter,
    }

    exporter_class = exporters.get(format.lower())
    if not exporter_class:
        raise ValueError(f"Unsupported export format: {format}")

    exporter = exporter_class(scan)
    return exporter.export()


def export_all_formats(scan) -> Dict[str, str]:
    """
    Export scan report in all formats

    Returns:
        Dict mapping format name to file path
    """
    formats = ['html', 'pdf', 'json', 'csv']
    results = {}

    for fmt in formats:
        try:
            results[fmt] = export_scan_report(scan, fmt)
        except Exception as e:
            results[fmt] = f"Error: {str(e)}"

    return results

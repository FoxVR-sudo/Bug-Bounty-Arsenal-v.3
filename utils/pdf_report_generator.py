"""
Professional PDF Report Generator with CVSS Scores and Executive Summary

Generates comprehensive security assessment reports.
"""
import logging
from datetime import datetime
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak
)
from io import BytesIO

logger = logging.getLogger(__name__)


class SecurityReportGenerator:
    """
    Generate professional security assessment PDF reports
    """

    def __init__(self, scan_data: Dict[str, Any]):
        self.scan = scan_data
        self.buffer = BytesIO()
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Create custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='Subtitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#666666'),
            spaceAfter=12,
            alignment=TA_CENTER
        ))

        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        # Finding title
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#e74c3c'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))

    def generate(self) -> BytesIO:
        """
        Generate complete PDF report

        Returns:
            BytesIO: PDF file buffer
        """
        doc = SimpleDocTemplate(
            self.buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )

        # Build document content
        story = []

        # Cover page
        story.extend(self._create_cover_page())
        story.append(PageBreak())

        # Executive summary
        story.extend(self._create_executive_summary())
        story.append(PageBreak())

        # Scan details
        story.extend(self._create_scan_details())
        story.append(Spacer(1, 0.5 * inch))

        # Vulnerability summary
        story.extend(self._create_vulnerability_summary())
        story.append(Spacer(1, 0.5 * inch))

        # Detailed findings
        story.extend(self._create_detailed_findings())
        story.append(PageBreak())

        # Remediation guide
        story.extend(self._create_remediation_guide())
        story.append(PageBreak())

        # Compliance mapping
        story.extend(self._create_compliance_mapping())

        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)

        self.buffer.seek(0)
        return self.buffer

    def _create_cover_page(self) -> List:
        """Create report cover page"""
        content = []

        # Spacer for centering
        content.append(Spacer(1, 2 * inch))

        # Title
        content.append(Paragraph(
            "Security Assessment Report",
            self.styles['CustomTitle']
        ))

        content.append(Spacer(1, 0.3 * inch))

        # Target info
        content.append(Paragraph(
            f"<b>Target:</b> {self.scan.get('target_url', 'N/A')}",
            self.styles['Subtitle']
        ))

        content.append(Spacer(1, 0.5 * inch))

        # Date
        scan_date = self.scan.get('created_at', datetime.now())
        if isinstance(scan_date, str):
            scan_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))

        content.append(Paragraph(
            f"Report Generated: {scan_date.strftime('%B %d, %Y')}",
            self.styles['Subtitle']
        ))

        content.append(Spacer(1, 1 * inch))

        # Severity summary box
        vulnerabilities = self.scan.get('results', {}).get('vulnerabilities', [])
        severity_counts = self._count_by_severity(vulnerabilities)

        summary_data = [
            ['CRITICAL', str(severity_counts.get('CRITICAL', 0))],
            ['HIGH', str(severity_counts.get('HIGH', 0))],
            ['MEDIUM', str(severity_counts.get('MEDIUM', 0))],
            ['LOW', str(severity_counts.get('LOW', 0))],
            ['INFO', str(severity_counts.get('INFO', 0))],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#c0392b')),
            ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#e67e22')),
            ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#f39c12')),
            ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#3498db')),
            ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#95a5a6')),
            ('TEXTCOLOR', (0, 0), (0, 4), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
        ]))

        content.append(summary_table)

        return content

    def _create_executive_summary(self) -> List:
        """Create executive summary section"""
        content = []

        content.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.2 * inch))

        vulnerabilities = self.scan.get('results', {}).get('vulnerabilities', [])
        severity_counts = self._count_by_severity(vulnerabilities)

        # Overall assessment
        total_vulns = len(vulnerabilities)
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)

        if critical_count > 0:
            risk_level = "CRITICAL"
            risk_color = "#c0392b"
        elif high_count > 0:
            risk_level = "HIGH"
            risk_color = "#e67e22"
        elif severity_counts.get('MEDIUM', 0) > 0:
            risk_level = "MEDIUM"
            risk_color = "#f39c12"
        else:
            risk_level = "LOW"
            risk_color = "#3498db"

        summary_text = f"""
        <para alignment="justify">
        This security assessment identified <b>{total_vulns} potential vulnerabilities</b>
        in the target application. The overall security risk level is classified as
        <b><font color="{risk_color}">{risk_level}</font></b>.
        </para>
        <br/>
        <para alignment="justify">
        The assessment included testing for common web application vulnerabilities including:
        XSS (Cross-Site Scripting), SQL Injection, SSRF, Authentication bypasses,
        Business logic flaws, and other OWASP Top 10 vulnerabilities.
        </para>
        """

        content.append(Paragraph(summary_text, self.styles['Normal']))
        content.append(Spacer(1, 0.3 * inch))

        # Key findings
        content.append(Paragraph("Key Findings", self.styles['Heading3']))

        # Get top 5 most severe findings
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: self._severity_to_number(x.get('severity', 'INFO')),
            reverse=True
        )[:5]

        for i, vuln in enumerate(sorted_vulns, 1):
            finding_text = f"{i}. <b>{vuln.get('title', 'Unknown')}</b> ({vuln.get('severity', 'INFO')})"
            content.append(Paragraph(finding_text, self.styles['Normal']))
            content.append(Spacer(1, 0.1 * inch))

        return content

    def _create_scan_details(self) -> List:
        """Create scan details section"""
        content = []

        content.append(Paragraph("Scan Details", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.2 * inch))

        scan_date = self.scan.get('created_at', datetime.now())
        if isinstance(scan_date, str):
            scan_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))

        details_data = [
            ['Target URL:', self.scan.get('target_url', 'N/A')],
            ['Scan Type:', self.scan.get('category', {}).get('name', 'N/A')],
            ['Scan Date:', scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Status:', self.scan.get('status', 'N/A').upper()],
            ['Duration:', f"{self.scan.get('duration', 0)} seconds"],
        ]

        details_table = Table(details_data, colWidths=[2 * inch, 4.5 * inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#2c3e50')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))

        content.append(details_table)

        return content

    def _create_vulnerability_summary(self) -> List:
        """Create vulnerability summary charts"""
        content = []

        content.append(Paragraph("Vulnerability Summary", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.2 * inch))

        vulnerabilities = self.scan.get('results', {}).get('vulnerabilities', [])
        severity_counts = self._count_by_severity(vulnerabilities)

        # Summary table
        summary_data = [
            ['Severity', 'Count', 'CVSS Range'],
            ['CRITICAL', str(severity_counts.get('CRITICAL', 0)), '9.0 - 10.0'],
            ['HIGH', str(severity_counts.get('HIGH', 0)), '7.0 - 8.9'],
            ['MEDIUM', str(severity_counts.get('MEDIUM', 0)), '4.0 - 6.9'],
            ['LOW', str(severity_counts.get('LOW', 0)), '0.1 - 3.9'],
            ['INFO', str(severity_counts.get('INFO', 0)), '0.0'],
        ]

        summary_table = Table(summary_data, colWidths=[2 * inch, 1.5 * inch, 2 * inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        content.append(summary_table)

        return content

    def _create_detailed_findings(self) -> List:
        """Create detailed findings section"""
        content = []

        content.append(Paragraph("Detailed Findings", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.2 * inch))

        vulnerabilities = self.scan.get('results', {}).get('vulnerabilities', [])

        # Sort by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: self._severity_to_number(x.get('severity', 'INFO')),
            reverse=True
        )

        for i, vuln in enumerate(sorted_vulns, 1):
            finding_content = self._create_finding_detail(i, vuln)
            content.extend(finding_content)
            content.append(Spacer(1, 0.3 * inch))

        return content

    def _create_finding_detail(self, number: int, vuln: Dict) -> List:
        """Create detailed finding entry"""
        content = []

        # Finding title with severity
        severity = vuln.get('severity', 'INFO')
        title = f"Finding #{number}: {vuln.get('title', 'Unknown Vulnerability')}"

        content.append(Paragraph(title, self.styles['FindingTitle']))

        # Severity badge
        severity_colors = {
            'CRITICAL': '#c0392b',
            'HIGH': '#e67e22',
            'MEDIUM': '#f39c12',
            'LOW': '#3498db',
            'INFO': '#95a5a6'
        }

        severity_color = severity_colors.get(severity, '#95a5a6')
        severity_text = (
            f'<para align="left"><b>Severity:</b> '
            f'<font color="{severity_color}">{severity}</font></para>'
        )
        content.append(Paragraph(severity_text, self.styles['Normal']))

        # CVSS Score (if available)
        cvss_score = vuln.get('cvss_score', 0.0)
        if cvss_score:
            cvss_text = f'<para align="left"><b>CVSS Score:</b> {cvss_score}/10.0</para>'
            content.append(Paragraph(cvss_text, self.styles['Normal']))

        content.append(Spacer(1, 0.1 * inch))

        # Description
        description = vuln.get('description', 'No description available.')
        content.append(Paragraph(f"<b>Description:</b><br/>{description}", self.styles['Normal']))
        content.append(Spacer(1, 0.1 * inch))

        # Evidence (if available)
        evidence = vuln.get('evidence', {})
        if evidence:
            evidence_text = "<b>Evidence:</b><br/>"
            for key, value in evidence.items():
                evidence_text += f"• {key}: {value}<br/>"
            content.append(Paragraph(evidence_text, self.styles['Normal']))
            content.append(Spacer(1, 0.1 * inch))

        # Remediation
        remediation = vuln.get('remediation', 'Consult with security team for remediation steps.')
        content.append(Paragraph(f"<b>Remediation:</b><br/>{remediation}", self.styles['Normal']))

        return content

    def _create_remediation_guide(self) -> List:
        """Create remediation guide section"""
        content = []

        content.append(Paragraph("Remediation Recommendations", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.2 * inch))

        recommendations = """
        <para alignment="justify">
        <b>Immediate Actions (Critical/High Severity):</b><br/>
        1. Review and patch all CRITICAL and HIGH severity vulnerabilities within 24-48 hours<br/>
        2. Implement input validation and output encoding<br/>
        3. Deploy Web Application Firewall (WAF) rules<br/>
        4. Conduct emergency security review<br/>
        <br/>
        <b>Short-term Actions (Medium Severity):</b><br/>
        1. Address MEDIUM severity findings within 1-2 weeks<br/>
        2. Implement secure coding practices<br/>
        3. Update third-party libraries and frameworks<br/>
        4. Enable security headers<br/>
        <br/>
        <b>Long-term Actions:</b><br/>
        1. Establish regular security testing schedule<br/>
        2. Implement security training for development team<br/>
        3. Adopt secure SDLC practices<br/>
        4. Deploy continuous security monitoring<br/>
        </para>
        """

        content.append(Paragraph(recommendations, self.styles['Normal']))

        return content

    def _create_compliance_mapping(self) -> List:
        """Create OWASP Top 10 compliance mapping"""
        content = []

        content.append(Paragraph("OWASP Top 10 Compliance", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.2 * inch))

        compliance_text = """
        <para alignment="justify">
        This assessment covers the following OWASP Top 10 2021 categories:
        <br/><br/>
        • A01:2021 – Broken Access Control<br/>
        • A02:2021 – Cryptographic Failures<br/>
        • A03:2021 – Injection<br/>
        • A04:2021 – Insecure Design<br/>
        • A05:2021 – Security Misconfiguration<br/>
        • A06:2021 – Vulnerable and Outdated Components<br/>
        • A07:2021 – Identification and Authentication Failures<br/>
        • A08:2021 – Software and Data Integrity Failures<br/>
        • A09:2021 – Security Logging and Monitoring Failures<br/>
        • A10:2021 – Server-Side Request Forgery (SSRF)<br/>
        </para>
        """

        content.append(Paragraph(compliance_text, self.styles['Normal']))

        return content

    def _add_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        canvas.saveState()

        # Header
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.grey)
        canvas.drawString(72, letter[1] - 50, "Security Assessment Report")
        canvas.drawRightString(letter[0] - 72, letter[1] - 50, datetime.now().strftime('%Y-%m-%d'))

        # Footer
        canvas.drawCentredString(letter[0] / 2, 30, f"Page {doc.page}")
        canvas.drawString(72, 30, "Confidential")
        canvas.drawRightString(letter[0] - 72, 30, "BugBounty Arsenal v3.0")

        canvas.restoreState()

    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _severity_to_number(self, severity: str) -> int:
        """Convert severity to number for sorting"""
        severity_map = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'INFO': 1
        }
        return severity_map.get(severity.upper(), 0)


def generate_pdf_report(scan_data: Dict[str, Any]) -> BytesIO:
    """
    Generate PDF report for a scan

    Args:
        scan_data: Scan data dictionary

    Returns:
        BytesIO: PDF file buffer
    """
    generator = SecurityReportGenerator(scan_data)
    return generator.generate()


# Export
__all__ = ['generate_pdf_report', 'SecurityReportGenerator']

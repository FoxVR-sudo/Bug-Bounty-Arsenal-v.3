from django.test import TestCase
from django.contrib.auth import get_user_model
from unittest.mock import patch

from scans.models import Scan, Vulnerability


class ScanFindingsStorageTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="tester@example.com",
            password="pass1234",
        )

    def _make_scan_with_findings(self, findings):
        return Scan.objects.create(
            user=self.user,
            target="https://example.com",
            scan_type="web_security",
            raw_results={"findings": findings},
        )

    def test_parse_and_store_findings_bulk_create(self):
        findings = [
            {
                "type": "XSS",
                "severity": "high",
                "url": "https://example.com/a",
                "detector": "xss_pattern_detector",
                "description": "xss",
                "evidence": "<script>",
            },
            {
                "type": "SQLi",
                "severity": "critical",
                "url": "https://example.com/b",
                "detector": "sql_pattern_detector",
                "description": "sqli",
                "evidence": "syntax error",
            },
        ]
        scan = self._make_scan_with_findings(findings)

        count = scan.parse_and_store_findings()

        self.assertEqual(count, 2)
        self.assertEqual(Vulnerability.objects.filter(scan=scan).count(), 2)

    def test_parse_and_store_findings_fallback_on_bulk_error(self):
        findings = [
            {
                "type": "CSRF",
                "severity": "medium",
                "url": "https://example.com/c",
                "detector": "csrf_detector",
                "description": "csrf",
                "evidence": "token missing",
            }
        ]
        scan = self._make_scan_with_findings(findings)

        with patch("scans.models.Vulnerability.objects.bulk_create", side_effect=Exception("fail")):
            count = scan.parse_and_store_findings()

        self.assertEqual(count, 1)
        self.assertEqual(Vulnerability.objects.filter(scan=scan).count(), 1)

    def test_parse_and_store_findings_empty(self):
        scan = self._make_scan_with_findings([])

        count = scan.parse_and_store_findings()

        self.assertEqual(count, 0)
        self.assertEqual(Vulnerability.objects.filter(scan=scan).count(), 0)

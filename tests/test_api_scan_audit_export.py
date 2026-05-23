import pytest
from rest_framework import status

from users.audit_models import ScanAuditLog


@pytest.mark.django_db
class TestScanAuditExport:
    @pytest.mark.api
    def test_scan_audit_export_csv(self, authenticated_client, test_user):
        ScanAuditLog.objects.create(
            user=test_user,
            action="scan_created",
            scan_type="web",
            target="https://example.com",
            ip_address="127.0.0.1",
            user_agent="pytest",
            metadata={},
        )

        url = "/api/scan-audit-logs/export/?export_format=csv&limit=100"
        res = authenticated_client.get(url)

        assert res.status_code == status.HTTP_200_OK
        assert "text/csv" in res["Content-Type"]

        body = b"".join(res.streaming_content).decode("utf-8")
        assert "id,created_at,user_email,action" in body
        assert "scan_created" in body
        assert "https://example.com" in body

    @pytest.mark.api
    def test_scan_audit_export_json(self, authenticated_client, test_user):
        ScanAuditLog.objects.create(
            user=test_user,
            action="scan_started",
            scan_type="web",
            target="https://example.com",
            ip_address="127.0.0.1",
            user_agent="pytest",
            metadata={},
        )

        url = "/api/scan-audit-logs/export/?export_format=json&limit=100"
        res = authenticated_client.get(url)

        assert res.status_code == status.HTTP_200_OK
        assert res.data["count"] >= 1
        assert any(r["action"] == "scan_started" for r in res.data["results"])

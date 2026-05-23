from rest_framework import serializers

from .audit_models import ScanAuditLog


class ScanAuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source="user.email", read_only=True)

    class Meta:
        model = ScanAuditLog
        fields = [
            "id",
            "scan",
            "user",
            "user_email",
            "action",
            "scan_type",
            "target",
            "ip_address",
            "user_agent",
            "geo_country",
            "geo_city",
            "geo_latitude",
            "geo_longitude",
            "vulnerabilities_found",
            "severity_critical",
            "severity_high",
            "severity_medium",
            "severity_low",
            "used_nuclei",
            "used_custom_payloads",
            "used_brute_force",
            "duration_seconds",
            "error_message",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields

from rest_framework import serializers
from .models import Scan, Vulnerability, AuditLog, ApiKey


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Serializer for Vulnerability model"""
    confidence_label = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'title', 'severity', 'detector', 'url', 'payload',
            'evidence', 'description', 'status_code', 'response_time',
            'is_verified', 'notes',
            'confidence', 'confidence_label', 'cvss_score',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'confidence', 'confidence_label', 'cvss_score', 'created_at', 'updated_at']

    def get_confidence_label(self, obj) -> str:
        from utils.scoring import confidence_label
        return confidence_label(obj.confidence)


class ScanSerializer(serializers.ModelSerializer):
    """Serializer for Scan model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    scan_category = serializers.CharField(source='scan_category.name', read_only=True)
    display_type = serializers.SerializerMethodField(read_only=True)

    consent = serializers.BooleanField(
        write_only=True,
        required=True,
        help_text='Required: confirm you are authorized to scan this target.'
    )

    # Support both 'detectors' and 'enabled_detectors' for backwards compatibility
    detectors = serializers.ListField(
        child=serializers.CharField(),
        write_only=True,
        required=False,
        help_text="List of detector names to run"
    )
    enabled_detectors = serializers.ListField(
        child=serializers.CharField(),
        write_only=True,
        required=False,
        help_text="List of detector names to run (deprecated, use 'detectors')"
    )

    class Meta:
        model = Scan
        fields = ['id', 'user', 'user_email', 'target', 'scan_type', 'scan_category',
                  'status', 'progress', 'current_step', 'severity_counts', 'vulnerabilities_found',
                  'display_type',
                  'consent',
                  'detectors', 'enabled_detectors',
                  'started_at', 'completed_at', 'report_path', 'celery_task_id', 'created_at']
        read_only_fields = ['id', 'user', 'status', 'progress', 'current_step', 'severity_counts',
                            'vulnerabilities_found', 'started_at', 'completed_at',
                            'report_path', 'celery_task_id', 'created_at']

    def create(self, validated_data):
        # Must be explicitly true
        validated_data.pop('consent', None)

        # Extract detectors (support both field names)
        detectors = validated_data.pop('detectors', None) or validated_data.pop('enabled_detectors', [])

        # User is set from request context in viewset
        validated_data['user'] = self.context['request'].user
        # Ensure raw_results has a default value for NOT NULL constraint
        if 'raw_results' not in validated_data:
            validated_data['raw_results'] = '{}'  # String representation for SQLite

        # Create the scan instance
        scan = super().create(validated_data)

        # Store detectors in the context for later use by start_async_scan
        # We'll pass it via the scan_config parameter
        scan._enabled_detectors = detectors

        return scan

    def validate_consent(self, value):
        if value is not True:
            raise serializers.ValidationError(
                'Consent is required. You must confirm you have authorization to scan this target.'
            )
        return value

    def get_display_type(self, obj):
        return obj.display_type_label


class ScanDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for Scan model with full results"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    scan_category = serializers.CharField(source='scan_category.name', read_only=True)
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    display_type = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Scan
        fields = ['id', 'user', 'user_email', 'target', 'scan_type', 'scan_category', 'status',
                  'progress', 'current_step', 'severity_counts', 'vulnerabilities_found',
                  'display_type',
                  'vulnerabilities', 'raw_results',
                  'started_at', 'completed_at', 'report_path', 'celery_task_id',
                  'created_at', 'updated_at', 'pid']
        read_only_fields = ['id', 'user', 'status', 'severity_counts',
                            'vulnerabilities_found', 'vulnerabilities', 'raw_results',
                            'started_at', 'completed_at',
                            'report_path', 'celery_task_id', 'created_at', 'updated_at', 'pid']

    def get_display_type(self, obj):
        return obj.display_type_label


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model (read-only)"""
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'user_email', 'event_type', 'description',
                  'ip_address', 'user_agent', 'extra_data', 'created_at']
        read_only_fields = ['id', 'user', 'event_type', 'description',
                            'ip_address', 'user_agent', 'extra_data', 'created_at']


class ApiKeySerializer(serializers.ModelSerializer):
    """Serializer for ApiKey model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = ApiKey
        fields = ['id', 'user', 'user_email', 'key', 'name', 'is_active',
                  'created_at', 'last_used_at']
        read_only_fields = ['id', 'user', 'key', 'created_at', 'last_used_at']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)

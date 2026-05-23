"""
Audit logging models for tracking all scan activities
"""
from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta


class ScanAuditLog(models.Model):
    """
    Enhanced audit log for tracking all scan operations (v3.0)
    Retention: 90 days with automatic cleanup
    """

    SCAN_TYPES = [
        ('recon', 'Recon Scan'),
        ('web', 'Web Scan'),
        ('api', 'API Scan'),
        ('vuln', 'Vulnerability Scan'),
        ('mobile', 'Mobile Scan'),
        ('custom', 'Custom Scan'),
    ]

    ACTION_TYPES = [
        ('scan_created', 'Scan Created'),
        ('scan_started', 'Scan Started'),
        ('scan_completed', 'Scan Completed'),
        ('scan_failed', 'Scan Failed'),
        ('scan_cancelled', 'Scan Cancelled'),
        ('report_downloaded', 'Report Downloaded'),
        ('dangerous_tool_used', 'Dangerous Tool Used'),
    ]

    # Reference
    scan = models.ForeignKey(
        'scans.Scan',
        on_delete=models.CASCADE,
        related_name='audit_logs_v3',
        null=True,
        blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scan_audit_logs')

    # Action details
    action = models.CharField(max_length=50, choices=ACTION_TYPES)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES, blank=True)
    target = models.TextField(help_text='Target URL/domain')

    # Network information
    ip_address = models.GenericIPAddressField(help_text='Source IP address')
    user_agent = models.TextField(blank=True, help_text='User agent string')

    # Geolocation (optional - can be populated async)
    geo_country = models.CharField(max_length=2, blank=True, help_text='ISO country code')
    geo_city = models.CharField(max_length=100, blank=True)
    geo_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    geo_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)

    # Results
    vulnerabilities_found = models.IntegerField(default=0)
    severity_critical = models.IntegerField(default=0)
    severity_high = models.IntegerField(default=0)
    severity_medium = models.IntegerField(default=0)
    severity_low = models.IntegerField(default=0)

    # Dangerous tools tracking (Enterprise only)
    used_nuclei = models.BooleanField(default=False)
    used_custom_payloads = models.BooleanField(default=False)
    used_brute_force = models.BooleanField(default=False)

    # Additional metadata
    duration_seconds = models.IntegerField(null=True, blank=True, help_text='Scan duration in seconds')
    error_message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True, help_text='Additional metadata')

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    # Retention warning
    deletion_warning_sent = models.BooleanField(default=False, help_text='Warning sent before auto-deletion')

    class Meta:
        db_table = 'scan_audit_logs_v3'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            models.Index(fields=['action']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.action} - {self.created_at}"

    @property
    def is_expired(self):
        """Check if log is older than 90 days"""
        return timezone.now() - self.created_at > timedelta(days=90)

    @property
    def days_until_deletion(self):
        """Days remaining until automatic deletion"""
        expiry_date = self.created_at + timedelta(days=90)
        remaining = expiry_date - timezone.now()
        return max(0, remaining.days)

    @classmethod
    def cleanup_old_logs(cls):
        """
        Delete logs older than 90 days
        Returns count of deleted logs
        """
        cutoff_date = timezone.now() - timedelta(days=90)
        old_logs = cls.objects.filter(created_at__lt=cutoff_date)
        count = old_logs.count()
        old_logs.delete()
        return count

    @classmethod
    def send_deletion_warnings(cls):
        """
        Send warnings for logs that will be deleted in 7 days
        Returns count of warnings sent
        """
        warning_date = timezone.now() - timedelta(days=83)  # 90 - 7
        cutoff_date = timezone.now() - timedelta(days=82)

        logs_to_warn = cls.objects.filter(
            created_at__lt=warning_date,
            created_at__gte=cutoff_date,
            deletion_warning_sent=False
        ).select_related('user')

        count = 0
        for log in logs_to_warn:
            # TODO: Send email notification
            log.deletion_warning_sent = True
            log.save(update_fields=['deletion_warning_sent'])
            count += 1

        return count

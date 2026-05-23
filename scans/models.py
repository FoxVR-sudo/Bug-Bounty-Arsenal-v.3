import logging
from django.db import models
from django.conf import settings
from django.utils import timezone
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


class Scan(models.Model):
    """Scan model - supports both legacy scan_type and new category-based scans"""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('stopped', 'Stopped'),
    ]

    # DEPRECATED - kept for backward compatibility
    SCAN_TYPE_CHOICES = [
        ('reconnaissance', 'Reconnaissance'),
        ('web_security', 'Web Security'),
        ('vulnerability', 'Vulnerability Scan'),
        ('api_security', 'API Security'),
        ('mobile', 'Mobile Security'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')
    target = models.CharField(max_length=500)

    # V3.0: New category-based scanning
    scan_category = models.ForeignKey(
        'scans.ScanCategory',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='category_scans',
        help_text='V3.0 scan category (replaces scan_type)'
    )
    selected_detectors = models.JSONField(
        default=list,
        blank=True,
        help_text='List of detector names to run (empty = all for category)'
    )

    # Legacy field - kept for backward compatibility
    scan_type = models.CharField(
        max_length=50,
        choices=SCAN_TYPE_CHOICES,
        default='web_security',
        blank=True,
        help_text='DEPRECATED: Use scan_category instead'
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Scan execution
    pid = models.IntegerField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=100, blank=True, null=True,
                                      help_text='Celery task ID for async execution')
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Progress tracking
    progress = models.IntegerField(default=0, help_text='Scan progress percentage (0-100)')
    current_step = models.CharField(max_length=200, blank=True, help_text='Current scan step/phase')

    # Results
    report_path = models.CharField(max_length=500, blank=True)
    vulnerabilities_found = models.IntegerField(default=0)
    severity_counts = models.JSONField(default=dict, blank=True)
    raw_results = models.JSONField(default=dict, blank=True, help_text='Full scan results data')

    # Storage management
    report_size_bytes = models.BigIntegerField(default=0, help_text='Total size of all report files in bytes')
    expires_at = models.DateTimeField(null=True, blank=True, help_text='When this scan result will be auto-deleted')

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scans'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        category = self.scan_category.name if self.scan_category else self.scan_type
        return f"{category} - {self.target} ({self.status})"

    @property
    def display_type_label(self):
        """Human-friendly scan type for admin/UI display.

        Prefer the v3 category label when available. If a scan was created with a
        detector selection and no category relation was stored, make a best-effort
        guess from the selected detectors. Finally, fall back to the legacy
        `scan_type` choices.
        """
        if getattr(self, 'scan_category_id', None) and getattr(self, 'scan_category', None):
            return getattr(self.scan_category, 'display_name', None) or getattr(self.scan_category, 'name', None)

        selected = getattr(self, 'selected_detectors', None) or []
        try:
            from detectors.detector_categories import guess_category_for_detectors

            guessed = guess_category_for_detectors(selected)
            if guessed and guessed.get('name'):
                return guessed['name']
        except Exception:
            pass

        if getattr(self, 'scan_type', None):
            try:
                return self.get_scan_type_display()
            except Exception:
                return self.scan_type

        return 'General'

    def start_async_scan(self, scan_config: dict = None):
        """
        Start the scan asynchronously using Celery.

        Args:
            scan_config: Optional configuration dict containing:
                - enabled_detectors: List of detector names to run
                - options: Scan options (concurrency, timeout, etc.)

        Returns:
            Celery task result
        """
        from scans.tasks import execute_scan_task

        if scan_config is None:
            scan_config = {}

        # Prepare scan configuration
        # Get user tier from subscription model
        user_tier = 'free'
        try:
            if hasattr(self.user, 'subscription') and self.user.subscription:
                subscription = self.user.subscription
                if hasattr(subscription, 'plan') and subscription.plan:
                    user_tier = subscription.plan.name
        except Exception:
            pass  # Default to 'free' if any error

        # Determine which detectors to run
        # Priority: 1) scan_config['enabled_detectors'], 2) self.selected_detectors, 3) all from category
        enabled_detectors = scan_config.get('enabled_detectors')

        if not enabled_detectors and self.scan_category:
            # Fallback to selected_detectors if available
            if self.selected_detectors:
                enabled_detectors = self.selected_detectors
            else:
                # Last resort: use all detectors from category
                enabled_detectors = list(
                    self.scan_category.get_detectors().values_list('name', flat=True)
                )

        # Ensure we have a list
        if not enabled_detectors:
            enabled_detectors = []

        email_verified = bool(getattr(self.user, 'is_verified', False))
        require_verified_email = bool(
            getattr(settings, 'DANGEROUS_TOOLS_REQUIRE_EMAIL_VERIFICATION', True)
        )
        try:
            domain_verified = DomainVerification.is_domain_verified_for_user(
                self.user,
                self.target,
            )
        except Exception:
            domain_verified = False

        dangerous_skip_reason = ''
        try:
            from scans.category_models import DetectorConfig

            dangerous_selected = DetectorConfig.objects.filter(
                is_active=True,
                is_dangerous=True,
                name__in=list(enabled_detectors or []),
            ).exists()
        except Exception:
            dangerous_selected = False

        if dangerous_selected:
            if not domain_verified:
                dangerous_skip_reason = 'domain_verification'
            elif require_verified_email and not email_verified:
                dangerous_skip_reason = 'email_verification'

        config = {
            'target': self.target,
            'scan_type': self.scan_type or 'web_security',  # Fallback for legacy
            'scan_category': self.scan_category.name if self.scan_category else None,
            'user_tier': user_tier,
            'dangerous_allowed': domain_verified and (
                email_verified or not require_verified_email
            ),
            'dangerous_skip_reason': dangerous_skip_reason,
            'enabled_detectors': enabled_detectors,
            'options': scan_config,
        }

        import logging
        logger = logging.getLogger(__name__)

        from kombu.exceptions import OperationalError
        from .exceptions import ScanBrokerUnavailable

        try:
            # Try to start Celery task
            task = execute_scan_task.apply_async(args=[self.id, config], ignore_result=True)

            # Store task ID
            self.celery_task_id = task.id
            self.status = 'pending'
            self.save(update_fields=['celery_task_id', 'status'])

            logger.info(f"Scan {self.id} started with Celery task {task.id}")
            return task
        except OperationalError as e:
            # Celery broker is unavailable
            logger.error(f"Failed to start Celery task for scan {self.id}: {e}")

            if getattr(settings, 'SCANS_FALLBACK_LOCAL_RUNNER', False):
                # Store config for the fallback runner process.
                raw = dict(self.raw_results or {})
                raw['queue_fallback'] = {
                    'reason': 'broker_unavailable',
                    'error': str(e),
                    'config': config,
                    'created_at': timezone.now().isoformat(),
                }
                self.raw_results = raw
                self.status = 'pending'
                self.current_step = 'Queued (fallback runner)'
                self.save(update_fields=['raw_results', 'status', 'current_step'])

                try:
                    project_root = Path(__file__).resolve().parent.parent
                    manage_py = project_root / 'manage.py'
                    python_exe = sys.executable or 'python'

                    # Launch a detached runner process so the HTTP request can return.
                    proc = subprocess.Popen(
                        [python_exe, str(manage_py), 'run_scan_fallback', str(self.id)],
                        cwd=str(project_root),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    self.celery_task_id = f'fallback:{proc.pid}'
                    self.save(update_fields=['celery_task_id'])
                    logger.warning(f"Scan {self.id} started via fallback runner pid={proc.pid}")
                    return proc
                except Exception as spawn_exc:
                    logger.exception("Failed to spawn fallback runner for scan %s", self.id)
                    self.status = 'failed'
                    self.current_step = f'Failed to start scan: {str(spawn_exc)[:100]}'
                    self.completed_at = timezone.now()
                    self.save(update_fields=['status', 'current_step', 'completed_at'])
                    raise ScanBrokerUnavailable(str(e))

            self.status = 'failed'
            self.current_step = f'Failed to start scan: {str(e)[:100]}'
            self.completed_at = timezone.now()
            self.save(update_fields=['status', 'current_step', 'completed_at'])
            raise ScanBrokerUnavailable(str(e))
        except Exception as e:
            # Celery not available - mark scan as failed
            logger.error(f"Failed to start Celery task for scan {self.id}: {e}")
            self.status = 'failed'
            self.current_step = f'Failed to start scan: {str(e)[:100]}'
            self.completed_at = timezone.now()
            self.save(update_fields=['status', 'current_step', 'completed_at'])
            raise  # Re-raise the exception so API returns error

    def cancel_scan(self):
        """Cancel a running or pending scan."""

        if self.status in ['running', 'pending']:
            # Revoke the Celery task if it exists
            if self.celery_task_id:
                from celery.result import AsyncResult
                try:
                    AsyncResult(self.celery_task_id).revoke(terminate=True)
                except Exception as exc:
                    # Broker/backends may be unavailable; cancellation remains best-effort but should be visible.
                    logger.exception("Failed to revoke Celery task for scan %s", self.id)
                    try:
                        raw = self.raw_results or {}
                        if isinstance(raw, str):
                            try:
                                import json
                                raw = json.loads(raw) if raw else {}
                            except Exception:
                                raw = {}
                        if not isinstance(raw, dict):
                            raw = {}
                        raw.setdefault('warnings', []).append({
                            'type': 'cancel_revoke_failed',
                            'celery_task_id': self.celery_task_id,
                            'error_type': type(exc).__name__,
                            'error': str(exc)[:500],
                        })
                        self.raw_results = raw
                        self.save(update_fields=['raw_results'])
                    except Exception:
                        logger.debug("Failed to persist cancel warning for scan %s", self.id)

            # Update status
            self.status = 'stopped'
            self.completed_at = timezone.now()
            self.save(update_fields=['status', 'completed_at'])

            return True
        return False

    def get_task_status(self):
        """Get the current status of the Celery task."""
        if not self.celery_task_id:
            return None

        from celery.result import AsyncResult
        try:
            task = AsyncResult(self.celery_task_id)
            return {
                'task_id': self.celery_task_id,
                'state': task.state,
                'info': task.info if task.info else {},
            }
        except Exception as exc:
            # If the broker/result backend is unavailable or misconfigured, fall back to DB.
            return {
                'task_id': self.celery_task_id,
                'state': self.status,
                'info': {
                    'warning': 'Celery backend unavailable; reporting DB status instead.',
                    'error': str(exc),
                },
            }

    def calculate_expiration(self):
        """Calculate when this scan should expire based on user tier."""
        if not self.completed_at:
            return None

        # Prefer plan.retention_days when available.
        days = 7
        try:
            from subscriptions.models import Subscription

            subscription = Subscription.objects.select_related('plan').filter(user=self.user).first()
            if subscription and getattr(subscription, 'plan', None):
                days = int(getattr(subscription.plan, 'retention_days', 7) or 7)
        except Exception:
            try:
                subscription = getattr(self.user, 'subscription', None)
                if subscription and getattr(subscription, 'plan', None):
                    days = int(getattr(subscription.plan, 'retention_days', 7) or 7)
            except Exception:
                days = 7

        days = max(1, days)
        from datetime import timedelta
        return self.completed_at + timedelta(days=days)

    def calculate_storage_size(self):
        """Calculate total storage used by this scan's files."""
        import os
        total_size = 0

        if self.report_path and os.path.exists(self.report_path):
            total_size += os.path.getsize(self.report_path)

        # Check for export files
        report_dir = os.path.dirname(self.report_path) if self.report_path else 'reports'
        scan_files = [
            f'{report_dir}/scan_{self.id}.html',
            f'{report_dir}/scan_{self.id}.pdf',
            f'{report_dir}/scan_{self.id}.json',
            f'{report_dir}/scan_{self.id}.csv',
        ]

        for file_path in scan_files:
            if os.path.exists(file_path):
                total_size += os.path.getsize(file_path)

        return total_size

    def update_storage_size(self):
        """Update the report_size_bytes field."""
        self.report_size_bytes = self.calculate_storage_size()
        self.save(update_fields=['report_size_bytes'])

    def is_expired(self):
        """Check if this scan has expired."""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at

    def delete_files(self):
        """Delete all files associated with this scan."""
        import os
        deleted_files = []

        if self.report_path and os.path.exists(self.report_path):
            os.remove(self.report_path)
            deleted_files.append(self.report_path)

        # Delete export files
        report_dir = os.path.dirname(self.report_path) if self.report_path else 'reports'
        scan_files = [
            f'{report_dir}/scan_{self.id}.html',
            f'{report_dir}/scan_{self.id}.pdf',
            f'{report_dir}/scan_{self.id}.json',
            f'{report_dir}/scan_{self.id}.csv',
        ]

        for file_path in scan_files:
            if os.path.exists(file_path):
                os.remove(file_path)
                deleted_files.append(file_path)

        return deleted_files

    def parse_and_store_findings(self):
        """Parse raw_results and create Vulnerability records."""
        if not self.raw_results:
            return 0

        findings = self.raw_results.get('findings', [])
        count = 0

        # Clear existing vulnerabilities first
        self.vulnerabilities.all().delete()

        from utils.scoring import score_finding_with_signal

        to_create = []
        for finding in findings:
            try:
                # Apply full signal-aware scoring (entropy, verified, signal_strength)
                score_finding_with_signal(finding)
                to_create.append(
                    Vulnerability(
                        scan=self,
                        title=finding.get('type', 'Unknown'),
                        description=finding.get('description', ''),
                        severity=finding.get('severity', 'low').lower(),
                        detector=finding.get('detector', 'unknown'),
                        url=finding.get('url', ''),
                        payload=finding.get('payload', ''),
                        evidence=finding.get('evidence', ''),
                        request_headers=finding.get('request_headers', {}),
                        response_headers=finding.get('response_headers', {}),
                        status_code=finding.get('status', None),
                        response_time=finding.get('response_time', None),
                        raw_data=finding,
                        confidence=finding.get('confidence', 50),
                        cvss_score=finding.get('cvss_score'),
                        is_verified=bool(finding.get('verified', False)),
                    )
                )
            except Exception as e:
                import logging
                logging.error(f"Error preparing vulnerability: {e}")

        if to_create:
            try:
                Vulnerability.objects.bulk_create(to_create, batch_size=500)
                count = len(to_create)
            except Exception as e:
                import logging
                logging.exception(f"Bulk create failed; falling back to individual saves: {e}")
                for obj in to_create:
                    try:
                        obj.save()
                        count += 1
                    except Exception as exc:
                        logging.error(f"Error storing vulnerability: {exc}")

        return count


class Vulnerability(models.Model):
    """Individual vulnerability finding from a scan"""

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=500, help_text='Vulnerability type/title')
    description = models.TextField(blank=True, help_text='Detailed description')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='low')
    detector = models.CharField(max_length=100, blank=True, help_text='Which detector found this')
    url = models.TextField(blank=True, help_text='Vulnerable URL')
    payload = models.TextField(blank=True, null=True, help_text='Payload used for exploitation')
    evidence = models.TextField(blank=True, help_text='Evidence of the vulnerability')
    request_headers = models.JSONField(default=dict, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True, help_text='Response time in seconds')
    raw_data = models.JSONField(default=dict, blank=True, help_text='Full raw finding data')
    is_verified = models.BooleanField(default=False, help_text='User verified this finding')
    notes = models.TextField(blank=True, help_text='User notes')

    # Scoring fields
    confidence = models.IntegerField(
        default=0,
        help_text='Detector confidence score 0-100%'
    )
    cvss_score = models.FloatField(
        null=True,
        blank=True,
        help_text='CVSS v3.1 base score (0.0-10.0)'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'vulnerabilities'
        ordering = ['-severity', '-created_at']
        indexes = [
            models.Index(fields=['scan', 'severity']),
            models.Index(fields=['detector']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['confidence']),
        ]

    def __str__(self):
        return f"{self.title} - {self.severity} ({self.scan_id})"


class AuditLog(models.Model):
    """Audit log for tracking admin actions"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs')
    event_type = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    extra_data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['event_type']),
        ]

    def __str__(self):
        return f"{self.event_type} - {self.created_at}"


class ApiKey(models.Model):
    """API keys for external integrations"""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=100)
    key = models.CharField(max_length=100, unique=True)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'api_keys'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} - {self.user.email}"

    def regenerate_key(self):
        """Generate a new random API key"""
        import secrets
        self.key = secrets.token_urlsafe(32)
        self.save()
        return self.key

    def save(self, *args, **kwargs):
        """Auto-generate key on creation"""
        if not self.key:
            import secrets
            self.key = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)


class DomainVerification(models.Model):
    """
    Domain ownership verification for dangerous scanner access.

    When a user wants to run dangerous detectors (e.g. command injection,
    SSRF, XXE, file upload probes) against a target, they must first prove
    they own that domain.  Two verification methods are supported:

    1. HTTP well-known: expose the token at
       https://<domain>/.well-known/bugbounty-arsenal-verify.txt
    2. DNS TXT record: add a TXT record to <domain> with value
       bugbounty-arsenal-verify=<token>

    Once verified the record is stored permanently (until the user removes
    it or an admin revokes it).  Superusers and staff are always exempt.
    """

    STATUS_PENDING = 'pending'
    STATUS_VERIFIED = 'verified'
    STATUS_FAILED = 'failed'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_VERIFIED, 'Verified'),
        (STATUS_FAILED, 'Failed'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='domain_verifications',
    )
    domain = models.CharField(
        max_length=253,
        help_text='Apex domain, e.g. example.com (no scheme, no path)',
    )
    token = models.CharField(max_length=64, unique=True)
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
    )
    verified_at = models.DateTimeField(null=True, blank=True)
    last_check_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'domain_verifications'
        unique_together = [('user', 'domain')]
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['domain', 'status']),
        ]

    def __str__(self):
        return f"{self.domain} ({self.status}) – {self.user.email}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_http_challenge_url(self):
        return f"https://{self.domain}/.well-known/bugbounty-arsenal-verify.txt"

    def get_dns_txt_value(self):
        return f"bugbounty-arsenal-verify={self.token}"

    @classmethod
    def is_domain_verified_for_user(cls, user, target_url: str) -> bool:
        """
        Return True when *user* has a verified record that covers the apex
        domain extracted from *target_url*.  Superusers/staff are always OK.
        """
        if getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False):
            return True

        apex = cls.extract_apex_domain(target_url)
        if not apex:
            return False

        return cls.objects.filter(
            user=user,
            status=cls.STATUS_VERIFIED,
            domain=apex,
        ).exists()

    @staticmethod
    def extract_apex_domain(url_or_domain: str) -> str:
        """
        Extract the apex domain (eTLD+1) from a URL or bare domain string.
        Falls back to simple last-two-labels heuristic.
        Returns lowercase string or ''.
        """
        from urllib.parse import urlparse

        raw = url_or_domain.strip()
        if raw.startswith(('http://', 'https://')):
            parsed = urlparse(raw)
            host = parsed.hostname or ''
        else:
            # Strip any path/port
            host = raw.split('/')[0].split(':')[0]

        host = host.lower().lstrip('www.')

        # Remove IP addresses — they cannot be "owned" via DNS
        import re
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            return ''

        return host

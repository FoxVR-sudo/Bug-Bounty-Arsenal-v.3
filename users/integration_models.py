"""
Integration models for third-party services
Available for Pro and Enterprise plans
"""
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError

from typing import Optional, Tuple, Set


class Integration(models.Model):
    """
    Third-party service integrations
    Supported: Slack, Jira, Discord, Telegram, GitHub, GitLab, Webhooks
    """

    INTEGRATION_TYPES = [
        ('slack', 'Slack'),
        ('jira', 'Jira'),
        ('discord', 'Discord'),
        ('telegram', 'Telegram'),
        ('github', 'GitHub'),
        ('gitlab', 'GitLab'),
        ('webhook', 'Custom Webhook'),
        ('email', 'Email Alerts'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
    ]

    EVENT_TYPES = [
        ('scan_started', 'Scan Started'),
        ('scan_completed', 'Scan Completed'),
        ('scan_failed', 'Scan Failed'),
        ('vulnerability_found', 'Vulnerability Found'),
        ('critical_vulnerability', 'Critical Vulnerability'),
        ('daily_report', 'Daily Report'),
        ('weekly_report', 'Weekly Report'),
    ]

    # Owner
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='integrations'
    )
    team = models.ForeignKey(
        'Team',
        on_delete=models.CASCADE,
        related_name='integrations',
        null=True,
        blank=True,
        help_text='Team integration (optional)'
    )

    # Integration details
    integration_type = models.CharField(max_length=20, choices=INTEGRATION_TYPES)
    name = models.CharField(max_length=255, help_text='Integration name/description')

    # Configuration (stored as JSON)
    config = models.JSONField(
        default=dict,
        help_text='Integration configuration (API keys, URLs, etc.)'
    )

    # Events to trigger
    events = models.JSONField(
        default=dict,
        help_text='Event triggers (dict of event flags or list of event names)'
    )

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    is_active = models.BooleanField(default=True)

    # Error tracking
    last_error = models.TextField(blank=True)
    last_error_at = models.DateTimeField(null=True, blank=True)
    error_count = models.IntegerField(default=0)

    # Statistics
    total_triggers = models.IntegerField(default=0, help_text='Total times triggered')
    successful_triggers = models.IntegerField(default=0)
    failed_triggers = models.IntegerField(default=0)
    last_triggered_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'integrations'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'integration_type']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.get_integration_type_display()} - {self.name}"

    def clean(self):
        """Validate integration configuration"""
        # Check user's subscription plan
        if hasattr(self.user, 'subscription'):
            plan = self.user.subscription.plan
            plan_name = getattr(plan, 'name', plan)
            if plan_name not in ['pro', 'enterprise']:
                raise ValidationError('Integrations are only available for Pro and Enterprise plans')

        # Validate required config fields
        required_fields = self._get_required_config_fields()
        for field in required_fields:
            if field not in self.config:
                raise ValidationError(f'Missing required configuration field: {field}')

    def _get_required_config_fields(self):
        """Get required config fields based on integration type"""
        config_requirements = {
            'slack': ['webhook_url'],
            'jira': ['webhook_url', 'api_key'],
            'discord': ['webhook_url'],
            'telegram': ['api_key', 'channel'],
            'github': ['api_key', 'webhook_url'],
            'gitlab': ['api_key', 'webhook_url'],
            'webhook': ['webhook_url'],
            'email': ['channel'],
        }
        return config_requirements.get(self.integration_type, [])

    def test_connection(self):
        """
        Test integration connection
        Returns (success: bool, message: str)
        """
        # TODO: Implement actual testing logic for each integration type
        try:
            if self.integration_type == 'slack':
                return self._test_slack()
            elif self.integration_type == 'jira':
                return self._test_jira()
            elif self.integration_type == 'discord':
                return self._test_discord()
            elif self.integration_type == 'webhook':
                return self._test_webhook()
            else:
                return True, 'Test connection not implemented yet'
        except Exception as e:
            return False, str(e)

    def _test_slack(self):
        """Test Slack webhook"""
        import requests
        url = self.config.get('webhook_url')
        response = requests.post(url, json={'text': 'BugBounty Arsenal - Connection test'}, timeout=10)
        if response.status_code == 200:
            return True, 'Slack connection successful'
        return False, f'Slack connection failed: {response.status_code}'

    def _test_discord(self):
        """Test Discord webhook"""
        import requests
        url = self.config.get('webhook_url')
        response = requests.post(url, json={'content': 'BugBounty Arsenal - Connection test'}, timeout=10)
        if response.status_code in [200, 204]:
            return True, 'Discord connection successful'
        return False, f'Discord connection failed: {response.status_code}'

    def _test_webhook(self):
        """Test custom webhook"""
        import requests
        url = self.config.get('webhook_url') or self.config.get('url')
        headers = self.config.get('headers', {})
        response = requests.post(url, json={'test': True}, headers=headers, timeout=10)
        if 200 <= response.status_code < 300:
            return True, 'Webhook connection successful'
        return False, f'Webhook connection failed: {response.status_code}'

    def _test_jira(self):
        """Test Jira connection"""
        # TODO: Implement Jira API test
        return True, 'Jira test not implemented yet'

    def trigger(self, event_type, data):
        """
        Trigger integration with event data
        Returns (success: bool, message: str)
        """
        if not self.is_active:
            return False, 'Integration is inactive'

        if isinstance(self.events, dict):
            if not self.events.get(event_type):
                return False, f'Event {event_type} not configured for this integration'
        else:
            if event_type not in self.events:
                return False, f'Event {event_type} not configured for this integration'

        self.total_triggers += 1

        try:
            success, message = self._send_notification(event_type, data)

            if success:
                self.successful_triggers += 1
                self.error_count = 0  # Reset error count on success
            else:
                self.failed_triggers += 1
                self.error_count += 1
                self.last_error = message
                from django.utils import timezone
                self.last_error_at = timezone.now()

                # Disable integration after 5 consecutive failures
                if self.error_count >= 5:
                    self.is_active = False
                    self.status = 'error'

            from django.utils import timezone
            self.last_triggered_at = timezone.now()
            self.save()

            return success, message

        except Exception as e:
            self.failed_triggers += 1
            self.error_count += 1
            self.last_error = str(e)
            from django.utils import timezone
            self.last_error_at = timezone.now()
            self.save()
            return False, str(e)

    def _send_notification(self, event_type, data):
        """Send notification based on integration type"""
        if self.integration_type == 'slack':
            return self._send_slack(event_type, data)
        elif self.integration_type == 'discord':
            return self._send_discord(event_type, data)
        elif self.integration_type == 'webhook':
            return self._send_webhook(event_type, data)
        elif self.integration_type == 'email':
            return self._send_email(event_type, data)
        else:
            return False, f'Integration type {self.integration_type} not implemented yet'

    def _send_slack(self, event_type, data):
        """Send Slack notification"""

        message = self._format_message(event_type, data)
        url = self.config.get('webhook_url')

        payload = {
            'text': message['title'],
            'attachments': [{
                'color': message['color'],
                'fields': [
                    {'title': k, 'value': v, 'short': True}
                    for k, v in message['fields'].items()
                ]
            }]
        }

        ok, status_code, err = self._post_json_with_retries(
            url,
            payload,
            timeout=10,
            ok_statuses={200},
        )
        if ok:
            return True, 'Slack notification sent'
        if status_code is not None:
            return False, f'Slack error: {status_code}'
        return False, f'Slack error: {err or "request_failed"}'

    def _send_discord(self, event_type, data):
        """Send Discord notification"""

        message = self._format_message(event_type, data)
        url = self.config.get('webhook_url')

        payload = {
            'content': message['title'],
            'embeds': [{
                'title': event_type.replace('_', ' ').title(),
                'color': int(message['color'].replace('#', ''), 16),
                'fields': [
                    {'name': k, 'value': v, 'inline': True}
                    for k, v in message['fields'].items()
                ]
            }]
        }

        ok, status_code, err = self._post_json_with_retries(
            url,
            payload,
            timeout=10,
            ok_statuses={200, 204},
        )
        if ok:
            return True, 'Discord notification sent'
        if status_code is not None:
            return False, f'Discord error: {status_code}'
        return False, f'Discord error: {err or "request_failed"}'

    def _send_webhook(self, event_type, data):
        """Send custom webhook"""
        import json
        import hmac
        import hashlib

        url = self.config.get('webhook_url') or self.config.get('url')
        headers = self.config.get('headers', {})
        if not isinstance(headers, dict):
            headers = {}

        signing_secret = self.config.get('signing_secret') or self.config.get('api_key')

        from django.utils import timezone
        payload_timestamp = timezone.now().isoformat()
        payload = {
            'event': event_type,
            'data': data,
            'timestamp': payload_timestamp,
        }

        raw_body: Optional[str] = None
        if signing_secret:
            # Canonical JSON body to make signature verification deterministic.
            raw_body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
            message = f"{payload_timestamp}.{raw_body}".encode("utf-8")
            signature = hmac.new(
                str(signing_secret).encode("utf-8"),
                msg=message,
                digestmod=hashlib.sha256,
            ).hexdigest()

            headers = {
                **headers,
                "Content-Type": "application/json",
                "X-BBA-Signature": signature,
                "X-BBA-Timestamp": payload_timestamp,
                "X-BBA-Event": str(event_type),
            }

        ok, status_code, err = self._post_json_with_retries(
            url,
            payload,
            headers=headers,
            timeout=10,
            ok_status_range=(200, 300),
            raw_body=raw_body,
        )
        if ok:
            return True, 'Webhook notification sent'
        if status_code is not None:
            return False, f'Webhook error: {status_code}'
        return False, f'Webhook error: {err or "request_failed"}'

    def _post_json_with_retries(
        self,
        url: str,
        payload: dict,
        *,
        headers: Optional[dict] = None,
        timeout: int = 10,
        ok_statuses: Optional[Set[int]] = None,
        ok_status_range: Optional[Tuple[int, int]] = None,
        raw_body: Optional[str] = None,
    ):
        """POST JSON with a small, production-safe retry policy.

        - Retries on network exceptions.
        - Retries on HTTP 429 and 5xx.
        - No sleeps/backoff (keeps scan completion fast).

        Returns (ok: bool, status_code: Optional[int], error: Optional[str]).
        """

        import requests

        if not url:
            return False, None, "missing_url"

        # Allow per-integration override via config, but keep defaults small.
        max_retries = int((self.config or {}).get("max_retries", 2) or 0)
        attempts = max(1, max_retries + 1)

        last_err: Optional[str] = None
        for attempt in range(attempts):
            try:
                if raw_body is not None:
                    response = requests.post(url, data=raw_body, headers=headers, timeout=timeout)
                else:
                    response = requests.post(url, json=payload, headers=headers, timeout=timeout)
                status_code = getattr(response, "status_code", None)

                ok = False
                if ok_statuses is not None:
                    ok = status_code in ok_statuses
                elif ok_status_range is not None:
                    lo, hi = ok_status_range
                    ok = status_code is not None and lo <= status_code < hi
                else:
                    ok = bool(status_code) and 200 <= status_code < 300

                if ok:
                    return True, status_code, None

                # Retry only for transient failures.
                if status_code in {429, 500, 502, 503, 504} and attempt < attempts - 1:
                    continue

                return False, status_code, None
            except requests.RequestException as exc:
                last_err = str(exc)
                if attempt < attempts - 1:
                    continue
                return False, None, last_err

        return False, None, last_err

    def _send_email(self, event_type, data):
        """Send email notification"""
        from django.core.mail import send_mail
        from django.conf import settings as django_settings

        message = self._format_message(event_type, data)
        recipients = self.config.get('recipients') or []
        if not recipients:
            channel = self.config.get('channel')
            if channel:
                recipients = [channel]

        send_mail(
            subject=message['title'],
            message='\n'.join([f"{k}: {v}" for k, v in message['fields'].items()]),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            fail_silently=False,
        )

        return True, 'Email sent'

    def _format_message(self, event_type, data):
        """Format notification message"""
        colors = {
            'scan_completed': '#28a745',  # Green
            'scan_failed': '#dc3545',  # Red
            'vulnerability_found': '#ffc107',  # Yellow
            'critical_vulnerability': '#dc3545',  # Red
        }

        return {
            'title': f"🔍 {event_type.replace('_', ' ').title()}",
            'color': colors.get(event_type, '#007bff'),
            'fields': {
                'Target': data.get('target', 'N/A'),
                'Scan Type': data.get('scan_type', 'N/A'),
                'Vulnerabilities': str(data.get('vulnerabilities_found', 0)),
                'Status': data.get('status', 'N/A'),
            }
        }

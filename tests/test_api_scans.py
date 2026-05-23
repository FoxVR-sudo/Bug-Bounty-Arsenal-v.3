"""
API Integration tests for scan endpoints
"""
import pytest
from django.urls import reverse
from django.test.utils import override_settings
from django.utils import timezone
from rest_framework import status
from scans.models import Scan
from users.audit_models import ScanAuditLog


class TestScanAPI:
    """Test /api/scans/ endpoints"""

    @pytest.mark.api
    def test_create_scan_authenticated(self, authenticated_client, user_subscription, scan_categories):
        """Test creating a scan with authenticated user"""
        url = reverse('api:scan-list')
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'consent': True,
            'detectors': ['xss_pattern_detector'],
        }

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert 'id' in response.data
        assert response.data['target'] == 'https://example.com'
        assert response.data['status'] in ['pending', 'failed']

    @pytest.mark.api
    @override_settings(SCANS_AUTO_START=True)
    def test_create_scan_writes_audit_logs(self, authenticated_client, test_user, user_subscription, scan_categories):
        """Audit trail: /api/scans/ create writes ScanAuditLog v3 entries."""
        url = reverse('api:scan-list')
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'consent': True,
            'detectors': ['xss_pattern_detector'],
            'options': {'timeout': 10},
        }

        before = ScanAuditLog.objects.filter(user=test_user).count()
        response = authenticated_client.post(url, data, format='json', HTTP_USER_AGENT='pytest')
        after = ScanAuditLog.objects.filter(user=test_user).count()

        assert response.status_code == status.HTTP_201_CREATED
        assert after >= before + 2

        created = ScanAuditLog.objects.filter(user=test_user, action='scan_created').order_by('-created_at').first()
        started = ScanAuditLog.objects.filter(user=test_user, action='scan_started').order_by('-created_at').first()
        assert created is not None
        assert started is not None
        assert created.target == 'https://example.com'
        assert started.target == 'https://example.com'

    @pytest.mark.api
    def test_create_scan_unauthenticated(self, api_client):
        """Test that unauthenticated users cannot create scans"""
        url = reverse('api:scan-list')
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'consent': True,
            'detectors': ['xss_pattern_detector'],
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.api
    def test_create_scan_exceeds_daily_limit(self, authenticated_client, user_subscription, scan_categories):
        """Test that users cannot exceed daily scan limits"""
        # Set daily scans to limit
        user_subscription.scans_used_today = user_subscription.plan.scans_per_day
        user_subscription.save()

        url = reverse('api:scan-list')
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'consent': True,
            'detectors': ['xss_pattern_detector'],
        }

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.api
    def test_create_scan_requires_consent(self, authenticated_client, user_subscription, scan_categories):
        """Consent gate: must explicitly confirm authorization."""
        url = reverse('api:scan-list')
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'detectors': ['xss_pattern_detector'],
        }

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.api
    def test_create_scan_rejects_false_consent(self, authenticated_client, user_subscription, scan_categories):
        """Consent gate: consent=false is rejected."""
        url = reverse('api:scan-list')
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'consent': False,
            'detectors': ['xss_pattern_detector'],
        }

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.api
    def test_list_user_scans(self, authenticated_client, test_user, scan_categories):
        """Test listing user's scans"""
        # Create test scans
        Scan.objects.create(
            user=test_user,
            target='https://example1.com',
            status='completed'
        )
        Scan.objects.create(
            user=test_user,
            target='https://example2.com',
            status='pending'
        )

        url = reverse('api:scan-list')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 2

    @pytest.mark.api
    def test_get_scan_details(self, authenticated_client, test_user, scan_categories):
        """Test retrieving scan details"""
        scan = Scan.objects.create(
            user=test_user,
            target='https://example.com',
            status='completed',
            raw_results={}
        )

        url = reverse('api:scan-detail', kwargs={'pk': scan.id})
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == scan.id
        assert response.data['target'] == 'https://example.com'

    @pytest.mark.api
    def test_cannot_access_other_users_scans(self, authenticated_client, test_admin, scan_categories):
        """Test that users cannot access other users' scans"""
        # Create scan for different user
        other_scan = Scan.objects.create(
            user=test_admin,
            target='https://private.com',
            status='completed'
        )

        url = reverse('api:scan-detail', kwargs={'pk': other_scan.id})
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.api
    def test_delete_scan(self, authenticated_client, test_user, scan_categories):
        """Test deleting a scan"""
        scan = Scan.objects.create(
            user=test_user,
            target='https://example.com',
            status='completed'
        )

        url = reverse('api:scan-detail', kwargs={'pk': scan.id})
        response = authenticated_client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Scan.objects.filter(id=scan.id).exists()

    @pytest.mark.api
    def test_scan_stats_has_profile_keys(self, authenticated_client):
        """Regression: /api/scans/stats/ returns Profile-friendly keys."""
        url = reverse('api:scan-stats')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        for key in [
            'daily_scans',
            'completed_today',
            'running_scans',
            'queued_scans',
            'monthly_scans',
            'monthly_completed',
            'monthly_vulnerabilities',
            'monthly_critical',
        ]:
            assert key in response.data

    @pytest.mark.api
    def test_cancel_scan_writes_audit_log(self, authenticated_client, test_user, scan_categories):
        """Audit trail: /api/scans/{id}/cancel/ writes scan_cancelled."""
        scan = Scan.objects.create(
            user=test_user,
            target='https://example.com',
            status='running',
            started_at=timezone.now(),
            celery_task_id='pytest-task',
        )

        url = reverse('api:scan-cancel', kwargs={'pk': scan.id})
        before = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()
        response = authenticated_client.post(url, {}, format='json', HTTP_USER_AGENT='pytest')
        after = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()

        assert response.status_code == status.HTTP_200_OK
        assert after == before + 1

    @pytest.mark.api
    def test_cancel_scan_is_idempotent(self, authenticated_client, test_user, scan_categories):
        """Cancel should return 200 even if scan is already stopped/completed."""
        scan = Scan.objects.create(
            user=test_user,
            target='https://example.com',
            status='stopped',
            started_at=timezone.now(),
            completed_at=timezone.now(),
        )

        url = reverse('api:scan-cancel', kwargs={'pk': scan.id})
        before = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()
        response = authenticated_client.post(url, {}, format='json', HTTP_USER_AGENT='pytest')
        after = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()

        assert response.status_code == status.HTTP_200_OK
        assert after == before

    @pytest.mark.api
    def test_scan_stop_view_writes_audit_log(self, authenticated_client, test_user, scan_categories):
        """Audit trail: /api/scans/stop/{id}/ writes scan_cancelled."""
        scan = Scan.objects.create(
            user=test_user,
            target='https://example.com',
            status='running',
            started_at=timezone.now(),
            celery_task_id='pytest-task',
        )

        url = reverse('scan-stop', kwargs={'scan_id': str(scan.id)})
        before = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()
        response = authenticated_client.post(url, {}, format='json', HTTP_USER_AGENT='pytest')
        after = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()

        assert response.status_code == status.HTTP_200_OK
        assert after == before + 1

    @pytest.mark.api
    def test_scan_stop_is_idempotent(self, authenticated_client, test_user, scan_categories):
        """Stop endpoint should return 200 if scan is already finished."""
        scan = Scan.objects.create(
            user=test_user,
            target='https://example.com',
            status='completed',
            started_at=timezone.now(),
            completed_at=timezone.now(),
        )

        url = reverse('scan-stop', kwargs={'scan_id': str(scan.id)})
        before = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()
        response = authenticated_client.post(url, {}, format='json', HTTP_USER_AGENT='pytest')
        after = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()

        assert response.status_code == status.HTTP_200_OK
        assert after == before


@pytest.mark.django_db
def test_cancel_scan_task_writes_audit_log(test_user):
    """Audit trail: cancel_scan_task writes scan_cancelled (system/celery source)."""
    from scans.tasks import cancel_scan_task

    scan = Scan.objects.create(
        user=test_user,
        target='https://example.com',
        status='running',
        started_at=timezone.now(),
        celery_task_id='pytest-task',
    )

    before = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()
    result = cancel_scan_task(scan.id)
    after = ScanAuditLog.objects.filter(user=test_user, action='scan_cancelled').count()

    assert result['status'] == 'stopped'
    assert after == before + 1


class TestScanCategoryAPI:
    """Test /api/categories/ endpoints"""

    @pytest.mark.api
    def test_list_categories(self, authenticated_client, scan_categories):
        """Test listing all scan categories"""
        url = reverse('api:scan-category-list')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 6  # 6 categories

    @pytest.mark.api
    def test_category_detector_count(self, authenticated_client, scan_categories, detector_configs):
        """Test that category shows detector count"""
        url = reverse('api:scan-category-list')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        # Each category should have detector_count field
        for category in response.data:
            assert 'detector_count' in category

    @pytest.mark.api
    def test_category_plan_restriction(self, authenticated_client, scan_categories):
        """Test that categories show required plan"""
        url = reverse('api:scan-category-list')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK

        # Find API category (requires pro)
        api_category = next(c for c in response.data if c['name'] == 'api')
        assert api_category['required_plan'] == 'pro'

        # Find Custom category (requires enterprise)
        custom_category = next(c for c in response.data if c['name'] == 'custom')
        assert custom_category['required_plan'] == 'enterprise'


class TestStartCategoryScan:
    @pytest.mark.api
    def test_start_category_scan_requires_consent(self, authenticated_client, user_subscription, scan_categories):
        """Consent gate: category scan endpoint must require consent=true."""
        web_category = next(c for c in scan_categories if c.name == 'web')

        url = '/api/scans/start-category-scan/'
        data = {
            'target': 'https://example.com',
            'category': web_category.id,
            'detectors': [],
            'options': {'timeout': 10},
        }

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.api
    @override_settings(SCANS_AUTO_START=True)
    def test_start_category_scan_creates_audit_logs(self, authenticated_client, test_user, user_subscription, scan_categories):
        """Audit trail: category scan start writes ScanAuditLog v3 entries."""
        web_category = next(c for c in scan_categories if c.name == 'web')

        url = '/api/scans/start-category-scan/'
        data = {
            'target': 'https://example.com',
            'category': web_category.id,
            'consent': True,
            'detectors': [],
            'options': {'timeout': 10},
        }

        before = ScanAuditLog.objects.filter(user=test_user).count()
        response = authenticated_client.post(url, data, format='json', HTTP_USER_AGENT='pytest')
        after = ScanAuditLog.objects.filter(user=test_user).count()

        assert response.status_code == status.HTTP_201_CREATED
        assert after >= before + 2

        created = ScanAuditLog.objects.filter(user=test_user, action='scan_created').order_by('-created_at').first()
        started = ScanAuditLog.objects.filter(user=test_user, action='scan_started').order_by('-created_at').first()
        assert created is not None
        assert started is not None
        assert created.target == 'https://example.com'
        assert started.target == 'https://example.com'


class TestStartScan:
    @pytest.mark.api
    def test_scan_start_view_requires_consent(self, authenticated_client, user_subscription, scan_categories):
        """Consent gate: /api/scans/start/ must require consent=true."""
        url = '/api/scans/start/'
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'detectors': ['xss_pattern_detector'],
        }

        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.api
    @override_settings(SCANS_AUTO_START=True)
    def test_scan_start_view_creates_audit_logs(self, authenticated_client, test_user, user_subscription, scan_categories):
        """Audit trail: /api/scans/start/ writes ScanAuditLog v3 entries."""
        url = '/api/scans/start/'
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'consent': True,
            'detectors': ['xss_pattern_detector'],
            'options': {'timeout': 10},
        }

        before = ScanAuditLog.objects.filter(user=test_user).count()
        response = authenticated_client.post(url, data, format='json', HTTP_USER_AGENT='pytest')
        after = ScanAuditLog.objects.filter(user=test_user).count()

        assert response.status_code == status.HTTP_201_CREATED
        assert after >= before + 2

        created = ScanAuditLog.objects.filter(user=test_user, action='scan_created').order_by('-created_at').first()
        started = ScanAuditLog.objects.filter(user=test_user, action='scan_started').order_by('-created_at').first()
        assert created is not None
        assert started is not None
        assert created.target == 'https://example.com'
        assert started.target == 'https://example.com'

    @pytest.mark.api
    def test_scan_start_view_enforces_daily_limit(self, authenticated_client, test_user, user_subscription, scan_categories):
        """/api/scans/start/ must not bypass subscription daily limits."""
        user_subscription.plan.scans_per_day = 1
        user_subscription.plan.save(update_fields=['scans_per_day'])

        url = '/api/scans/start/'
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'detectors': ['xss_pattern_detector'],
            'consent': True,
        }

        first = authenticated_client.post(url, data, format='json')
        assert first.status_code == status.HTTP_201_CREATED

        second = authenticated_client.post(url, data, format='json')
        assert second.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.api
    def test_scan_start_view_enforces_concurrent_limit(self, authenticated_client, test_user, user_subscription, scan_categories):
        """/api/scans/start/ must enforce concurrent scan limits."""
        from scans.models import Scan

        user_subscription.plan.concurrent_scans = 1
        user_subscription.plan.save(update_fields=['concurrent_scans'])

        Scan.objects.create(user=test_user, target='https://example.com', status='running')

        url = '/api/scans/start/'
        data = {
            'target': 'https://example.org',
            'scan_type': 'web_security',
            'detectors': ['xss_pattern_detector'],
            'consent': True,
        }

        res = authenticated_client.post(url, data, format='json')
        assert res.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.api
    def test_scan_start_returns_503_when_broker_unavailable(self, authenticated_client, test_user, user_subscription, scan_categories, monkeypatch, settings):
        """If Celery broker is down, scan start should fail fast with 503 (not 500)."""
        from kombu.exceptions import OperationalError
        import scans.tasks as scan_tasks

        settings.SCANS_AUTO_START = True
        settings.SCANS_FALLBACK_LOCAL_RUNNER = False

        def _raise(*args, **kwargs):
            raise OperationalError('broker down')

        monkeypatch.setattr(scan_tasks.execute_scan_task, 'apply_async', _raise)

        url = '/api/scans/start/'
        data = {
            'target': 'https://example.com',
            'scan_type': 'web_security',
            'consent': True,
            'detectors': ['xss_pattern_detector'],
        }

        response = authenticated_client.post(url, data, format='json', HTTP_USER_AGENT='pytest')
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

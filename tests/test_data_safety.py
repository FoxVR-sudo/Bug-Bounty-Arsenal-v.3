import os
import tempfile

import pytest
from rest_framework import status
from rest_framework.test import APIClient


@pytest.mark.api
@pytest.mark.django_db
def test_admin_database_backup_creates_file(test_admin):
    from django.urls import reverse

    client = APIClient()
    client.force_authenticate(user=test_admin)

    url = reverse('admin-database-backup')
    res = client.post(url, {}, format='json')
    assert res.status_code == status.HTTP_200_OK

    backup_file = res.data.get('backup_file')
    assert backup_file
    assert os.path.exists(backup_file)
    assert int(res.data.get('bytes') or 0) > 0
    assert res.data.get('sha256')


@pytest.mark.api
@pytest.mark.django_db
def test_admin_database_restore_verify_only(test_admin):
    from django.urls import reverse

    client = APIClient()
    client.force_authenticate(user=test_admin)

    backup_res = client.post(reverse('admin-database-backup'), {}, format='json')
    assert backup_res.status_code == status.HTTP_200_OK
    backup_file = backup_res.data['backup_file']

    restore_res = client.post(
        reverse('admin-database-restore'),
        {'backup_file': backup_file},
        format='json',
    )
    assert restore_res.status_code == status.HTTP_200_OK
    assert restore_res.data.get('applied') is False
    assert restore_res.data.get('integrity_check') in ('ok', 'OK', 'Ok')


@pytest.mark.unit
@pytest.mark.django_db
def test_cleanup_expired_scans_task_deletes_scan_and_files(test_user, user_subscription):
    from datetime import timedelta

    from django.utils import timezone

    from scans.models import Scan
    from scans.tasks import cleanup_expired_scans_task

    now = timezone.now()

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, 'report.json')
        with open(report_path, 'wb') as f:
            f.write(b'{}')

        scan = Scan.objects.create(
            user=test_user,
            target='https://example.com',
            status='completed',
            completed_at=now - timedelta(days=10),
            report_path=report_path,
            expires_at=now - timedelta(days=1),
        )

        # Create export files that delete_files() will attempt to remove.
        for suffix in ('html', 'pdf', 'json', 'csv'):
            path = os.path.join(tmpdir, f'scan_{scan.id}.{suffix}')
            with open(path, 'wb') as f:
                f.write(b'x')

        result = cleanup_expired_scans_task()
        assert result['status'] == 'success'
        assert result['deleted'] >= 1

        assert not Scan.objects.filter(id=scan.id).exists()
        assert not os.path.exists(report_path)
        for suffix in ('html', 'pdf', 'json', 'csv'):
            assert not os.path.exists(os.path.join(tmpdir, f'scan_{scan.id}.{suffix}'))


@pytest.mark.unit
@pytest.mark.django_db
def test_scan_expiration_follows_plan_retention_days(test_user, free_plan, pro_plan, enterprise_plan):
    from datetime import timedelta

    from django.utils import timezone

    from scans.models import Scan
    from subscriptions.models import Subscription

    now = timezone.now().replace(microsecond=0)

    def _check_plan(plan, expected_days):
        subscription, _ = Subscription.objects.get_or_create(
            user=test_user,
            defaults={'plan': plan, 'status': 'active'},
        )
        subscription.plan = plan
        subscription.save(update_fields=['plan'])

        scan = Scan.objects.create(
            user=test_user,
            target='https://example.com',
            status='completed',
            completed_at=now,
        )

        assert scan.calculate_expiration() == now + timedelta(days=expected_days)

    _check_plan(free_plan, 7)
    _check_plan(pro_plan, 30)
    _check_plan(enterprise_plan, 90)

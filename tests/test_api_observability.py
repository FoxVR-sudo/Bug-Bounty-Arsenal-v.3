import pytest
from rest_framework.test import APIClient
from rest_framework import status


@pytest.mark.api
@pytest.mark.django_db
def test_healthz_is_public():
    client = APIClient()
    res = client.get('/healthz/')
    assert res.status_code == status.HTTP_200_OK
    assert res.data['status'] == 'ok'


@pytest.mark.api
@pytest.mark.django_db
def test_readyz_is_public_and_ok_by_default():
    client = APIClient()
    res = client.get('/readyz/')
    assert res.status_code == status.HTTP_200_OK
    assert res.data['status'] == 'ok'
    assert 'components' in res.data
    assert res.data['components']['database'] == 'ok'


@pytest.mark.api
@pytest.mark.django_db
def test_admin_scan_metrics_requires_admin(test_user):
    client = APIClient()
    client.force_authenticate(user=test_user)

    res = client.get('/api/admin/scan-metrics/')
    assert res.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.api
@pytest.mark.django_db
def test_admin_scan_metrics_returns_payload(test_admin):
    from scans.models import Scan

    Scan.objects.create(user=test_admin, target='https://example.com', status='completed')

    client = APIClient()
    client.force_authenticate(user=test_admin)

    res = client.get('/api/admin/scan-metrics/?hours=24')
    assert res.status_code == status.HTTP_200_OK
    assert 'window' in res.data
    assert 'scans' in res.data
    assert 'timing_seconds' in res.data
    assert res.data['scans']['total'] >= 1

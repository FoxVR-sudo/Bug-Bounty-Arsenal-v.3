import pytest
from rest_framework import status


@pytest.mark.api
@pytest.mark.django_db
def test_export_json_allows_pending_scan_and_streams(authenticated_client, test_user):
    from scans.models import Scan

    scan = Scan.objects.create(user=test_user, target='https://example.com', status='pending')

    res = authenticated_client.get(f'/api/scans/{scan.id}/json/')
    assert res.status_code == status.HTTP_200_OK
    assert getattr(res, 'streaming', False) is True
    assert res['Content-Type'].startswith('application/json')

    content = b''.join(
        chunk if isinstance(chunk, (bytes, bytearray)) else str(chunk).encode('utf-8')
        for chunk in res.streaming_content
    )
    assert b'"status"' in content
    assert b'"pending"' in content
    assert b'"vulnerabilities"' in content


@pytest.mark.api
@pytest.mark.django_db
def test_export_csv_streams(authenticated_client, test_user):
    from scans.models import Scan, Vulnerability

    scan = Scan.objects.create(user=test_user, target='https://example.com', status='completed')
    Vulnerability.objects.create(scan=scan, title='XSS', severity='high', detector='xss_pattern_detector')

    res = authenticated_client.get(f'/api/scans/{scan.id}/csv/')
    assert res.status_code == status.HTTP_200_OK
    assert getattr(res, 'streaming', False) is True
    assert res['Content-Type'].startswith('text/csv')

    first_chunk = next(iter(res.streaming_content))
    if isinstance(first_chunk, str):
        first_chunk = first_chunk.encode('utf-8')
    assert b'Title,Severity,Detector' in first_chunk


@pytest.mark.api
@pytest.mark.django_db
def test_export_json_returns_413_when_too_large(authenticated_client, test_user, settings):
    from scans.models import Scan, Vulnerability

    settings.EXPORT_MAX_VULNERABILITIES_JSON = 1

    scan = Scan.objects.create(user=test_user, target='https://example.com', status='completed')
    Vulnerability.objects.create(scan=scan, title='A', detector='d')
    Vulnerability.objects.create(scan=scan, title='B', detector='d')

    res = authenticated_client.get(f'/api/scans/{scan.id}/json/')
    assert res.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


@pytest.mark.api
@pytest.mark.django_db
def test_export_csv_returns_413_when_too_large(authenticated_client, test_user, settings):
    from scans.models import Scan, Vulnerability

    settings.EXPORT_MAX_VULNERABILITIES_CSV = 1

    scan = Scan.objects.create(user=test_user, target='https://example.com', status='completed')
    Vulnerability.objects.create(scan=scan, title='A', detector='d')
    Vulnerability.objects.create(scan=scan, title='B', detector='d')

    res = authenticated_client.get(f'/api/scans/{scan.id}/csv/')
    assert res.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


@pytest.mark.api
@pytest.mark.django_db
def test_export_pdf_returns_413_when_too_large(authenticated_client, test_user, settings):
    from scans.models import Scan, Vulnerability

    settings.EXPORT_MAX_VULNERABILITIES_PDF = 1

    scan = Scan.objects.create(user=test_user, target='https://example.com', status='completed')
    Vulnerability.objects.create(scan=scan, title='A', detector='d')
    Vulnerability.objects.create(scan=scan, title='B', detector='d')

    res = authenticated_client.get(f'/api/scans/{scan.id}/pdf/')
    assert res.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


@pytest.mark.api
@pytest.mark.django_db
def test_export_endpoints_scoped_to_owner(authenticated_client, test_user):
    from django.contrib.auth import get_user_model

    from scans.models import Scan

    User = get_user_model()
    other_user = User.objects.create_user(
        email='other@example.com',
        password='pass12345',
        first_name='Other',
        middle_name='M',
        last_name='User',
        phone='+12345678902',
        is_verified=True,
    )

    scan = Scan.objects.create(user=other_user, target='https://example.com', status='completed')

    assert authenticated_client.get(f'/api/scans/{scan.id}/json/').status_code == status.HTTP_404_NOT_FOUND
    assert authenticated_client.get(f'/api/scans/{scan.id}/csv/').status_code == status.HTTP_404_NOT_FOUND
    assert authenticated_client.get(f'/api/scans/{scan.id}/pdf/').status_code == status.HTTP_404_NOT_FOUND

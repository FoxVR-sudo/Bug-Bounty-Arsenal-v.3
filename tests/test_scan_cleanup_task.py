import pytest


@pytest.mark.django_db
def test_cleanup_stuck_scans_task_marks_stuck_pending_and_running_failed(test_user):
    from datetime import timedelta

    from django.utils import timezone

    from scans.models import Scan
    from scans.tasks import cleanup_stuck_scans_task
    from users.audit_models import ScanAuditLog

    now = timezone.now()

    stuck_pending = Scan.objects.create(user=test_user, target='https://pending-stuck.example', status='pending')
    stuck_running = Scan.objects.create(user=test_user, target='https://running-stuck.example', status='running', started_at=now)

    fresh_pending = Scan.objects.create(user=test_user, target='https://pending-fresh.example', status='pending')
    fresh_running = Scan.objects.create(user=test_user, target='https://running-fresh.example', status='running', started_at=now)

    # Make two scans "stuck" by pushing timestamps beyond cutoffs.
    Scan.objects.filter(id=stuck_pending.id).update(created_at=now - timedelta(minutes=31))
    Scan.objects.filter(id=stuck_running.id).update(started_at=now - timedelta(minutes=121))

    result = cleanup_stuck_scans_task(pending_minutes=30, running_minutes=120)

    assert result['status'] == 'success'
    assert result['updated'] == 2
    assert result['pending_checked'] == 1
    assert result['running_checked'] == 1

    stuck_pending.refresh_from_db()
    stuck_running.refresh_from_db()
    fresh_pending.refresh_from_db()
    fresh_running.refresh_from_db()

    assert stuck_pending.status == 'failed'
    assert stuck_pending.completed_at is not None
    assert stuck_pending.current_step == 'Marked failed by cleanup (stuck scan)'

    assert stuck_running.status == 'failed'
    assert stuck_running.completed_at is not None
    assert stuck_running.current_step == 'Marked failed by cleanup (stuck scan)'

    assert fresh_pending.status == 'pending'
    assert fresh_pending.completed_at is None

    assert fresh_running.status == 'running'
    assert fresh_running.completed_at is None

    # Audit logs should be created for stuck scans only.
    pending_audit = ScanAuditLog.objects.filter(
        scan=stuck_pending,
        action='scan_failed',
        error_message='stuck_scan_cleanup',
    )
    running_audit = ScanAuditLog.objects.filter(
        scan=stuck_running,
        action='scan_failed',
        error_message='stuck_scan_cleanup',
    )

    assert pending_audit.count() == 1
    assert running_audit.count() == 1

    assert pending_audit.first().metadata.get('source') == 'celery:cleanup_stuck_scans_task'
    assert pending_audit.first().metadata.get('previous_status') == 'pending'

    assert running_audit.first().metadata.get('source') == 'celery:cleanup_stuck_scans_task'
    assert running_audit.first().metadata.get('previous_status') == 'running'

    assert ScanAuditLog.objects.filter(scan=fresh_pending).count() == 0
    assert ScanAuditLog.objects.filter(scan=fresh_running).count() == 0

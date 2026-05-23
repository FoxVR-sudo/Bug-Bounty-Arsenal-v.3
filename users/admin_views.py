"""
Admin API views for user and system management.
Requires admin/staff permissions.
"""
import logging
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status

from scans.models import Scan
from subscriptions.models import Subscription

User = get_user_model()
logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_scan_metrics(request):
    """Scan metrics for dashboards/alerts (admin-only).

    Query params:
      - hours: int (default 24)
    """
    try:
        hours = int(request.query_params.get('hours', '24'))
    except ValueError:
        hours = 24
    hours = max(1, min(hours, 24 * 30))

    now = timezone.now()
    window_start = now - timedelta(hours=hours)

    qs = Scan.objects.filter(created_at__gte=window_start)

    total = qs.count()
    by_status = {row['status']: row['count'] for row in qs.values('status').annotate(count=Count('id'))}
    failed = int(by_status.get('failed', 0) or 0)
    completed = int(by_status.get('completed', 0) or 0)

    failure_rate = (failed / total) if total else 0.0

    duration_values = []
    queue_values = []
    for row in qs.values('created_at', 'started_at', 'completed_at'):
        created_at = row.get('created_at')
        started_at = row.get('started_at')
        completed_at = row.get('completed_at')

        if created_at and started_at:
            queue_values.append(max(0.0, (started_at - created_at).total_seconds()))
        if started_at and completed_at:
            duration_values.append(max(0.0, (completed_at - started_at).total_seconds()))

    def _summary(values):
        if not values:
            return {'count': 0, 'avg': None, 'p50': None, 'p95': None}
        values_sorted = sorted(values)
        count = len(values_sorted)
        avg = sum(values_sorted) / count

        def _pct(p):
            if count == 1:
                return values_sorted[0]
            idx = int(round((p / 100.0) * (count - 1)))
            idx = max(0, min(count - 1, idx))
            return values_sorted[idx]

        return {
            'count': count,
            'avg': round(avg, 3),
            'p50': round(_pct(50), 3),
            'p95': round(_pct(95), 3),
        }

    return Response(
        {
            'window': {
                'hours': hours,
                'start': window_start.isoformat(),
                'end': now.isoformat(),
            },
            'scans': {
                'total': total,
                'by_status': by_status,
                'completed': completed,
                'failed': failed,
                'failure_rate': round(failure_rate, 4),
            },
            'timing_seconds': {
                'queue_time': _summary(queue_values),
                'duration': _summary(duration_values),
            },
        }
    )


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_stats(request):
    """
    Get comprehensive dashboard statistics.

    Returns:
        - User statistics (total, active, new this month)
        - Scan statistics (total, by status)
        - Subscription statistics
        - Revenue metrics (if available)
    """
    now = timezone.now()
    month_ago = now - timedelta(days=30)

    # User statistics
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    new_users_this_month = User.objects.filter(date_joined__gte=month_ago).count()

    # Scan statistics
    total_scans = Scan.objects.count()
    scans_by_status = Scan.objects.values('status').annotate(count=Count('id'))
    scans_this_month = Scan.objects.filter(created_at__gte=month_ago).count()

    # Subscription statistics
    active_subscriptions = Subscription.objects.filter(status='active').count()
    subscriptions_by_plan = Subscription.objects.filter(
        status='active'
    ).values('plan__name').annotate(count=Count('id'))

    # Recent activity
    recent_scans = Scan.objects.order_by('-created_at')[:5].values(
        'id', 'target', 'status', 'created_at', 'user__email'
    )

    return Response({
        'users': {
            'total': total_users,
            'active': active_users,
            'new_this_month': new_users_this_month,
            'inactive': total_users - active_users,
        },
        'scans': {
            'total': total_scans,
            'this_month': scans_this_month,
            'by_status': {item['status']: item['count'] for item in scans_by_status},
        },
        'subscriptions': {
            'active': active_subscriptions,
            'by_plan': {item['plan__name']: item['count'] for item in subscriptions_by_plan},
        },
        'recent_activity': {
            'recent_scans': list(recent_scans),
        },
        'timestamp': now.isoformat(),
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_users_list(request):
    """
    List all users with filtering and search capabilities.

    Query parameters:
        - search: Search by email
        - is_active: Filter by active status (true/false)
        - has_subscription: Filter users with active subscriptions
    """
    queryset = User.objects.all()

    # Search filter
    search = request.query_params.get('search', '')
    if search:
        queryset = queryset.filter(Q(email__icontains=search))

    # Active filter
    is_active = request.query_params.get('is_active', None)
    if is_active is not None:
        queryset = queryset.filter(is_active=is_active.lower() == 'true')

    # Subscription filter
    has_subscription = request.query_params.get('has_subscription', None)
    if has_subscription is not None:
        if has_subscription.lower() == 'true':
            queryset = queryset.filter(subscription__status='active').distinct()
        else:
            queryset = queryset.exclude(subscription__status='active').distinct()

    # Annotate with scan count
    queryset = queryset.annotate(scan_count=Count('scans'))

    users_data = queryset.values(
        'id',
        'email',
        'is_active',
        'is_staff',
        'date_joined',
        'last_login',
        'registration_ip',
        'registration_city',
        'registration_country',
        'registration_latitude',
        'registration_longitude',
        'registration_is_anonymous',
        'registration_is_proxy',
        'registration_is_vpn',
        'registration_is_tor',
        'registration_is_hosting',
        'last_seen_ip',
        'last_seen_city',
        'last_seen_country',
        'last_seen_latitude',
        'last_seen_longitude',
        'last_seen_is_anonymous',
        'last_seen_is_proxy',
        'last_seen_is_vpn',
        'last_seen_is_tor',
        'last_seen_is_hosting',
        'scan_count',
    ).order_by('-date_joined')

    return Response({
        'count': queryset.count(),
        'results': list(users_data),
    })


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_user_activate(request, user_id):
    """
    Activate a user account.
    """
    try:
        user = User.objects.get(id=user_id)
        user.is_active = True
        user.save()
        logger.info(f"Admin {request.user.email} activated user {user.email}")
        return Response({
            'message': f'User {user.email} activated successfully',
            'user_id': user.id,
            'is_active': user.is_active,
        })
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_user_deactivate(request, user_id):
    """
    Deactivate a user account.
    Prevents login but preserves data.
    """
    try:
        user = User.objects.get(id=user_id)

        # Prevent self-deactivation
        if user.id == request.user.id:
            return Response(
                {'error': 'Cannot deactivate your own account'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.is_active = False
        user.save()
        logger.info(f"Admin {request.user.email} deactivated user {user.email}")

        return Response({
            'message': f'User {user.email} deactivated successfully',
            'user_id': user.id,
            'is_active': user.is_active,
        })
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_scans_list(request):
    """
    List all scans across all users.

    Query parameters:
        - status: Filter by scan status
        - user_id: Filter by user
        - date_from: Filter scans created after this date (ISO format)
        - date_to: Filter scans created before this date (ISO format)
    """
    queryset = Scan.objects.select_related('user').all()

    # Status filter
    scan_status = request.query_params.get('status', '')
    if scan_status:
        queryset = queryset.filter(status=scan_status)

    # User filter
    user_id = request.query_params.get('user_id', '')
    if user_id:
        queryset = queryset.filter(user_id=user_id)

    # Date range filters
    date_from = request.query_params.get('date_from', '')
    if date_from:
        queryset = queryset.filter(created_at__gte=date_from)

    date_to = request.query_params.get('date_to', '')
    if date_to:
        queryset = queryset.filter(created_at__lte=date_to)

    scans_data = queryset.values(
        'id', 'target', 'status', 'created_at', 'updated_at',
        'user__email', 'user__id', 'scan_type'
    ).order_by('-created_at')[:100]  # Limit to 100 for performance

    return Response({
        'count': queryset.count(),
        'results': list(scans_data),
    })


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_database_backup(request):
    """
    Create a database backup.

    Currently supports SQLite by copying the configured DB file.
    """
    import hashlib
    import time
    from pathlib import Path
    from django.db import connection
    import sqlite3

    try:
        engine = (connection.settings_dict.get('ENGINE') or '').lower()
        if 'sqlite' not in engine:
            return Response(
                {'error': 'Database backup not implemented for this engine'},
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )

        backup_dir = Path('backups')
        backup_dir.mkdir(exist_ok=True)

        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_path = backup_dir / f'db_backup_{timestamp}.db'

        # Use SQLite online backup so this works for both file-backed and
        # in-memory/shared-memory SQLite databases used by test runners.
        connection.ensure_connection()
        src = connection.connection
        if src is None:
            raise RuntimeError('Database connection is not initialized')

        def _backup_via_iterdump(src_conn, path):
            dst_conn = sqlite3.connect(str(path))
            try:
                dst_conn.execute('PRAGMA journal_mode=OFF;')
                dst_conn.execute('PRAGMA synchronous=OFF;')
                dst_conn.execute('BEGIN;')
                for line in src_conn.iterdump():
                    if line in ('BEGIN TRANSACTION;', 'COMMIT;'):
                        continue
                    dst_conn.execute(line)
                dst_conn.execute('COMMIT;')
            finally:
                dst_conn.close()

        dst = sqlite3.connect(str(backup_path))
        try:
            src.execute('PRAGMA busy_timeout=5000;')
            start_time = time.monotonic()

            def _progress(status, remaining, total):
                if time.monotonic() - start_time > 15:
                    raise TimeoutError('SQLite backup timed out')

            src.backup(dst, pages=1000, progress=_progress, sleep=0.01)
        except TimeoutError:
            logger.warning('Database backup timed out; falling back to iterdump')
            dst.close()
            if backup_path.exists():
                backup_path.unlink(missing_ok=True)
            _backup_via_iterdump(src, backup_path)
        finally:
            try:
                dst.close()
            except Exception:
                pass

        sha256 = hashlib.sha256()
        with backup_path.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                sha256.update(chunk)

        logger.info(f"Database backup created by {request.user.email}: {backup_path}")

        return Response({
            'message': 'Database backup created successfully',
            'backup_file': str(backup_path),
            'timestamp': timestamp,
            'bytes': backup_path.stat().st_size,
            'sha256': sha256.hexdigest(),
        })
    except Exception as e:
        logger.error(f"Database backup failed: {str(e)}")
        return Response(
            {'error': f'Backup failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_database_restore(request):
    """
    Restore database from backup.

    Safe-by-default:
    - verify_only (default): validates that the backup is a readable SQLite DB and passes integrity_check.
    - apply=true: applies restore to the configured SQLite DB file (guarded by ALLOW_DB_RESTORE=true
      and a confirmation string).
    """
    from pathlib import Path
    import os
    import sqlite3
    from django.conf import settings
    from django.db import connection

    backup_file = request.data.get('backup_file', '')
    apply_restore = str(request.data.get('apply', 'false')).lower() in ('1', 'true', 'yes', 'on')
    confirm = request.data.get('confirm', '')

    if not backup_file:
        return Response(
            {'error': 'backup_file parameter is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    backup_path = Path(backup_file)

    if not backup_path.exists():
        return Response(
            {'error': 'Backup file not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    # Verify backup integrity (always allowed)
    try:
        conn = sqlite3.connect(str(backup_path))
        try:
            row = conn.execute('PRAGMA integrity_check;').fetchone()
            integrity = row[0] if row else 'unknown'
        finally:
            conn.close()
    except Exception as exc:
        return Response(
            {'error': f'Backup verification failed: {str(exc)}'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not apply_restore:
        logger.info(f"Database restore verify-only by {request.user.email}: {backup_file}")
        return Response({
            'message': 'Backup verified',
            'backup_file': backup_file,
            'integrity_check': integrity,
            'applied': False,
        })

    # Apply restore (guarded)
    if os.getenv('ALLOW_DB_RESTORE', 'false').lower() not in ('1', 'true', 'yes', 'on'):
        return Response(
            {'error': 'DB restore is disabled (set ALLOW_DB_RESTORE=true to enable).'},
            status=status.HTTP_403_FORBIDDEN,
        )

    if confirm != 'I_UNDERSTAND_THIS_WILL_OVERWRITE_DB':
        return Response(
            {'error': 'Missing confirm string.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    engine = (connection.settings_dict.get('ENGINE') or '').lower()
    if 'sqlite' not in engine:
        return Response(
            {'error': 'Database restore not implemented for this engine'},
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

    db_name = settings.DATABASES.get('default', {}).get('NAME')
    if not db_name or str(db_name) == ':memory:':
        return Response(
            {'error': 'Cannot apply restore to in-memory SQLite DB'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Do an online restore into the destination DB file.
    try:
        src = sqlite3.connect(str(backup_path))
        dst = sqlite3.connect(str(db_name))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
    except Exception as exc:
        logger.exception("Database restore failed")
        return Response(
            {'error': f'Restore failed: {str(exc)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    logger.warning(f"Database restore APPLIED by {request.user.email}: {backup_file}")

    return Response({
        'message': 'Database restore applied',
        'backup_file': backup_file,
        'integrity_check': integrity,
        'applied': True,
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_system_health(request):
    """
    Check system health and component status.
    """
    import psutil
    from django.db import connection

    # Database check
    db_status = 'healthy'
    try:
        connection.ensure_connection()
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'

    # Celery check
    celery_status = 'unknown'
    try:
        from config.celery import app as celery_app
        inspect = celery_app.control.inspect()
        stats = inspect.stats()
        if stats:
            celery_status = f'healthy ({len(stats)} workers)'
        else:
            celery_status = 'no workers available'
    except Exception as e:
        celery_status = f'error: {str(e)}'

    # System metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return Response({
        'status': 'healthy',
        'components': {
            'database': db_status,
            'celery': celery_status,
        },
        'system': {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available_gb': round(memory.available / (1024**3), 2),
            'disk_percent': disk.percent,
            'disk_free_gb': round(disk.free / (1024**3), 2),
        },
        'timestamp': timezone.now().isoformat(),
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_celery_status(request):
    """
    Get detailed Celery worker and task status.
    """
    try:
        from config.celery import app as celery_app
        inspect = celery_app.control.inspect()

        # Get worker stats
        stats = inspect.stats()
        active_tasks = inspect.active()
        scheduled_tasks = inspect.scheduled()
        reserved_tasks = inspect.reserved()

        return Response({
            'workers': stats or {},
            'active_tasks': active_tasks or {},
            'scheduled_tasks': scheduled_tasks or {},
            'reserved_tasks': reserved_tasks or {},
            'timestamp': timezone.now().isoformat(),
        })
    except Exception as e:
        logger.error(f"Failed to get Celery status: {str(e)}")
        return Response(
            {'error': f'Celery inspection failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_clear_cache(request):
    """
    Clear application cache.
    """
    try:
        from django.core.cache import cache
        cache.clear()
        logger.info(f"Cache cleared by admin {request.user.email}")

        return Response({
            'message': 'Cache cleared successfully',
            'timestamp': timezone.now().isoformat(),
        })
    except Exception as e:
        logger.error(f"Failed to clear cache: {str(e)}")
        return Response(
            {'error': f'Cache clear failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

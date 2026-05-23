from __future__ import annotations

import logging
from typing import Any, cast

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Run a scan synchronously as a broker-down fallback. "
        "Intended to be spawned by Scan.start_async_scan() when Celery broker is unavailable."
    )

    def add_arguments(self, parser):
        parser.add_argument('scan_id', type=int)

    def handle(self, *args, **options):
        from scans.models import Scan
        from scans.tasks import execute_scan_task

        scan_id = int(options['scan_id'])

        try:
            scan = Scan.objects.get(id=scan_id)
        except Scan.DoesNotExist as exc:
            raise CommandError(f"Scan {scan_id} does not exist") from exc

        # Avoid re-running finished scans.
        if scan.status in {'running', 'completed', 'failed', 'stopped'}:
            self.stdout.write(self.style.WARNING(f"Scan {scan_id} is already {scan.status}; nothing to do"))
            return

        raw = scan.raw_results or {}
        fallback = (raw.get('queue_fallback') or {}) if isinstance(raw, dict) else {}
        config = fallback.get('config') if isinstance(fallback, dict) else None

        if not isinstance(config, dict):
            # Last-resort reconstruction (should not normally happen).
            user_tier = 'free'
            try:
                if hasattr(scan.user, 'subscription') and scan.user.subscription:
                    subscription = scan.user.subscription
                    if hasattr(subscription, 'plan') and subscription.plan:
                        user_tier = subscription.plan.name
            except Exception:
                pass

            enabled_detectors = []
            if scan.selected_detectors:
                enabled_detectors = scan.selected_detectors
            elif scan.scan_category:
                enabled_detectors = list(scan.scan_category.get_detectors().values_list('name', flat=True))

            config = {
                'target': scan.target,
                'scan_type': scan.scan_type or 'web_security',
                'scan_category': scan.scan_category.name if scan.scan_category else None,
                'user_tier': user_tier,
                'enabled_detectors': enabled_detectors,
                'options': {},
            }

            raw = dict(raw) if isinstance(raw, dict) else {}
            raw['queue_fallback'] = {
                'reason': 'missing_config_reconstructed',
                'config': config,
                'created_at': timezone.now().isoformat(),
            }
            scan.raw_results = raw
            scan.save(update_fields=['raw_results'])

        # Mark that the fallback runner actually started.
        try:
            raw = dict(scan.raw_results or {})
            qf = raw.get('queue_fallback')
            if isinstance(qf, dict):
                qf = dict(qf)
                qf['started_at'] = timezone.now().isoformat()
                raw['queue_fallback'] = qf
                scan.raw_results = raw
                scan.save(update_fields=['raw_results'])
        except Exception:
            logger.exception("Failed to persist queue_fallback started_at for scan %s", scan_id)

        self.stdout.write(self.style.SUCCESS(f"Running scan {scan_id} via fallback runner"))

        try:
            # Execute synchronously within this process.
            task = cast(Any, execute_scan_task)
            task.run(scan_id, config)
        except Exception as exc:
            logger.exception("Fallback scan runner failed for scan %s", scan_id)
            try:
                scan.refresh_from_db()
                scan.status = 'failed'
                scan.current_step = f"Fallback runner failed: {str(exc)[:180]}"
                scan.completed_at = timezone.now()
                raw = dict(scan.raw_results or {})
                qf = raw.get('queue_fallback')
                if isinstance(qf, dict):
                    qf = dict(qf)
                    qf['failed_at'] = timezone.now().isoformat()
                    qf['error'] = str(exc)
                    raw['queue_fallback'] = qf
                scan.raw_results = raw
                scan.save(update_fields=['status', 'current_step', 'completed_at', 'raw_results'])
            except Exception:
                logger.exception("Failed to mark scan %s failed after fallback runner error", scan_id)
            raise CommandError(f"Fallback runner failed: {exc}") from exc

        # Best-effort stamp completion.
        try:
            scan.refresh_from_db()
            raw = dict(scan.raw_results or {})
            qf = raw.get('queue_fallback')
            if isinstance(qf, dict):
                qf = dict(qf)
                qf['completed_at'] = timezone.now().isoformat()
                raw['queue_fallback'] = qf
                scan.raw_results = raw
                scan.save(update_fields=['raw_results'])
        except Exception:
            logger.exception("Failed to persist queue_fallback completed_at for scan %s", scan_id)

        self.stdout.write(self.style.SUCCESS(f"Scan {scan_id} fallback runner finished"))

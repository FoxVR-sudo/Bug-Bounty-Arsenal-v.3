from __future__ import annotations

import json
import time
from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from scans.models import Scan


class Command(BaseCommand):
    help = (
        "End-to-end scan pipeline diagnostic: creates a Scan row, enqueues Celery task, "
        "polls DB until completion, then prints a short summary."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--email",
            required=True,
            help="User email to own the diagnostic scan (must exist)",
        )
        parser.add_argument(
            "--target",
            required=True,
            help="Target URL (must be reachable from the worker)",
        )
        parser.add_argument(
            "--detector",
            action="append",
            dest="detectors",
            default=[],
            help="Detector name to run (repeatable). Example: --detector security_headers_detector",
        )
        parser.add_argument(
            "--timeout-seconds",
            type=int,
            default=120,
            help="How long to wait for completion (default: 120)",
        )
        parser.add_argument(
            "--poll-interval",
            type=float,
            default=1.0,
            help="Seconds between DB polls (default: 1.0)",
        )
        parser.add_argument(
            "--scan-type",
            default="web_security",
            help="Legacy scan_type value (default: web_security)",
        )

    def handle(self, *args: Any, **options: Any):
        email: str = options["email"]
        target: str = options["target"]
        detectors: list[str] = options["detectors"]
        timeout_seconds: int = options["timeout_seconds"]
        poll_interval: float = options["poll_interval"]
        scan_type: str = options["scan_type"]

        if not detectors:
            detectors = ["security_headers_detector"]

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist as exc:
            raise CommandError(f"User not found: {email}") from exc

        with transaction.atomic():
            scan = Scan.objects.create(
                user=user,
                target=target,
                scan_type=scan_type,
                status="pending",
                progress=0,
                current_step="diag: created",
                raw_results={},
            )
            scan.selected_detectors = detectors
            scan.save(update_fields=["selected_detectors"])

        self.stdout.write(self.style.SUCCESS(f"created_scan id={scan.id} user={email}"))
        self.stdout.write(f"enqueue_detectors={detectors}")

        scan_config = {
            "concurrency": 5,
            "timeout": 15,
            "per_host_rate": 1.0,
            "allow_destructive": True,
            "bypass_cloudflare": False,
            "enable_forbidden_probe": False,
            "scan_mode": "normal",
            "enabled_detectors": detectors,
        }

        try:
            scan.start_async_scan(scan_config)
        except Exception as exc:
            raise CommandError(f"Failed to enqueue scan via Celery: {exc}") from exc

        self.stdout.write(self.style.SUCCESS(f"enqueued celery_task_id={scan.celery_task_id}"))

        deadline = time.time() + timeout_seconds
        last_status = None
        while time.time() < deadline:
            scan.refresh_from_db()
            if scan.status != last_status:
                self.stdout.write(
                    f"status={scan.status} progress={scan.progress} step={scan.current_step}"
                )
                last_status = scan.status

            if scan.status in ("completed", "failed", "stopped"):
                break

            time.sleep(poll_interval)

        scan.refresh_from_db()
        self.stdout.write(self.style.SUCCESS("final"))
        self.stdout.write(
            json.dumps(
                {
                    "id": scan.id,
                    "status": scan.status,
                    "progress": scan.progress,
                    "current_step": scan.current_step,
                    "vulnerabilities_found": scan.vulnerabilities_found,
                    "severity_counts": scan.severity_counts,
                    "celery_task_id": scan.celery_task_id,
                },
                indent=2,
                default=str,
            )
        )

        if scan.status not in ("completed", "failed", "stopped"):
            raise CommandError(
                "Timed out waiting for scan completion. "
                "If web can create scans but they never complete, check: "
                "(1) celery worker is running, (2) broker URL, (3) DB is shared between web and worker."
            )

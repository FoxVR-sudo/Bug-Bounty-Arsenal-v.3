"""
Celery tasks for asynchronous scan execution.

This module contains Celery tasks that execute security scans in the background,
integrating with the existing detector system and updating scan results in real-time.
"""

import os
import json
import logging
import shutil
import subprocess
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from celery import shared_task
from django.utils import timezone
from scans.websocket_utils import send_scan_update, send_scan_complete, send_scan_error

logger = logging.getLogger(__name__)


def _resolve_tool_binary(bin_name: str, env_var_name: Optional[str]) -> Optional[str]:
    """Best-effort resolve external tool binary path.

    Celery/cPanel environments often have a minimal PATH. We support:
    1) Explicit env var override (SUBFINDER_BIN/AMASS_BIN)
    2) shutil.which() on PATH
    3) Common install locations (e.g. ~/go/bin/*, /usr/local/bin/*)
    """

    # 1) Explicit override
    override_env = os.environ.get(env_var_name) if env_var_name else None
    if override_env:
        override_env = str(override_env).strip()
        if override_env and os.path.exists(override_env) and os.access(override_env, os.X_OK):
            return override_env

    # 2) PATH lookup
    which = shutil.which(bin_name)
    if which:
        return which

    # 3) Common locations
    home = os.path.expanduser('~')
    candidates = [
        os.path.join(home, 'go', 'bin', bin_name),
        os.path.join(home, '.local', 'bin', bin_name),
        os.path.join('/usr/local/bin', bin_name),
        os.path.join('/usr/bin', bin_name),
    ]
    for cand in candidates:
        try:
            if os.path.exists(cand) and os.access(cand, os.X_OK):
                return cand
        except Exception:
            continue

    return None


def _extract_domain_from_target(target: str) -> Optional[str]:
    if not isinstance(target, str) or not target.strip():
        return None

    t = target.strip()
    parsed = urlparse(t if '://' in t else f'https://{t}')
    host = (parsed.hostname or '').strip()
    return host or None


def _derive_scheme_from_target(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        return 'https'
    t = target.strip()
    if '://' not in t:
        return 'https'
    parsed = urlparse(t)
    return (parsed.scheme or 'https').lower()


def _run_external_lines(cmd: List[str], *, timeout_seconds: int) -> Dict[str, Any]:
    if not cmd:
        return {'ok': False, 'error': 'empty_command', 'lines': []}

    bin_name = cmd[0]

    env_var_name: Optional[str] = None

    # Allow explicit binary path override to avoid PATH issues in Celery/Docker.
    if bin_name == 'subfinder':
        env_var_name = 'SUBFINDER_BIN'
    elif bin_name == 'amass':
        env_var_name = 'AMASS_BIN'
    elif bin_name == 'katana':
        env_var_name = 'KATANA_BIN'
    elif bin_name == 'ffuf':
        env_var_name = 'FFUF_BIN'
    elif bin_name == 'dalfox':
        env_var_name = 'DALFOX_BIN'
    elif bin_name == 'gf':
        env_var_name = 'GF_BIN'

    resolved = _resolve_tool_binary(bin_name, env_var_name)
    if resolved:
        cmd = [resolved] + cmd[1:]
        bin_name = resolved
    else:
        env_value = os.environ.get(env_var_name) if env_var_name else None
        hint = (
            f"Install '{cmd[0]}' or set {env_var_name} to its absolute path"
            if env_var_name
            else 'Install the tool or set an absolute binary path'
        )
        return {
            'ok': False,
            'error': 'binary_not_found',
            'binary': bin_name,
            'env_var': env_var_name,
            'env_value': str(env_value).strip() if env_value is not None else None,
            'hint': hint,
            'lines': [],
        }

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'timeout', 'binary': bin_name, 'lines': []}
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'binary': bin_name, 'lines': []}

    stdout = (completed.stdout or '').splitlines()
    stderr = (completed.stderr or '').strip()
    lines = [line.strip() for line in stdout if line and line.strip()]

    return {
        'ok': completed.returncode == 0,
        'binary': bin_name,
        'returncode': completed.returncode,
        'stderr': (stderr[:2000] if stderr else ''),
        'lines': lines,
    }


@shared_task(bind=True, max_retries=3, ignore_result=True)
def execute_scan_task(self, scan_id: int, scan_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a security scan asynchronously.

    Args:
        scan_id: The ID of the Scan model instance
        scan_config: Configuration dictionary containing:
            - target: Target URL or domain
            - scan_type: Type of scan to perform
            - user_tier: User's subscription tier
            - enabled_detectors: List of detector names to run
            - options: Additional scan options

    Returns:
        Dictionary with scan results and metadata
    """
    from scans.models import Scan

    try:
        # Get the scan instance
        scan = Scan.objects.get(id=scan_id)

        # Update status to running
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.progress = 0
        scan.current_step = 'Initializing scanner...'
        scan.save(update_fields=['status', 'started_at', 'progress', 'current_step'])

        # Send WebSocket update
        send_scan_update(scan_id, {
            'status': 'running',
            'progress': 0,
            'current_step': 'Initializing scanner...',
            'started_at': scan.started_at.isoformat()
        })

        logger.info(f"Starting scan {scan_id} for target: {scan_config['target']}")

        # Extract configuration
        target = scan_config['target']
        scan_type = scan_config.get('scan_type', 'web_security')
        scan_category = scan_config.get('scan_category')
        user_tier = scan_config.get('user_tier', 'free')
        enabled_detectors = scan_config.get('enabled_detectors', [])
        options = scan_config.get('options', {})

        # Optional detector-specific configuration (passed through UI/API)
        nuclei_templates = options.get('nuclei_templates')
        nuclei_severity = options.get('nuclei_severity')
        cve_db_path = options.get('cve_db_path')

        # enabled_detectors should always be provided by the API
        # If empty, the scan should have been rejected at the API level
        if not enabled_detectors:
            error_msg = "No detectors selected for scan. This should have been caught by the API."
            logger.error(error_msg)
            scan.status = 'failed'
            scan.current_step = error_msg
            scan.completed_at = timezone.now()
            scan.save(update_fields=['status', 'current_step', 'completed_at'])

            # Audit (best-effort)
            try:
                from users.scan_audit import create_scan_audit_log_system

                create_scan_audit_log_system(
                    scan=scan,
                    action='scan_failed',
                    error_message=error_msg,
                    metadata={
                        'source': 'celery:execute_scan_task',
                        'celery_task_id': getattr(self.request, 'id', None),
                        'reason': 'no_detectors',
                    },
                )
            except Exception:
                logger.exception("Failed writing audit log for scan %s (no_detectors)", scan_id)
            return

        logger.info(f"Scan {scan_id} will run {len(enabled_detectors)} detectors: {enabled_detectors}")

        # Prepare scan context
        scan_context = {
            'scan_id': scan_id,
            'user_tier': user_tier,
            'scan_mode': options.get('scan_mode', 'normal'),
            'run_all_selected_detectors': options.get('run_all_selected_detectors', False),
            'output_dir': f'reports/scan_{scan_id}',
            'auto_confirm': True,  # Auto-confirm for async execution
            'concurrency': options.get('concurrency', 10),
            'timeout': options.get('timeout', 15),
            'per_host_rate': options.get('per_host_rate', 1.0),
            'allow_destructive': options.get('allow_destructive', True),
            'bypass_cloudflare': options.get('bypass_cloudflare', False),
            'enable_forbidden_probe': options.get('enable_forbidden_probe', False),
            'enabled_detectors': enabled_detectors,
            # pass-through options used by optional detectors
            'nuclei_templates': nuclei_templates,
            'nuclei_severity': nuclei_severity,
            'cve_db_path': cve_db_path,
            'nmap_preset': options.get('nmap_preset', 'service'),
            'nmap_custom': options.get('nmap_custom', ''),
        }

        # Import scanner module
        import scanner

        # Update progress
        scan.progress = 10
        scan.current_step = f'Preparing scan targets... ({len(enabled_detectors)} detectors)'
        scan.save(update_fields=['progress', 'current_step'])
        send_scan_update(scan_id, {
            'progress': 10,
            'current_step': f'Preparing scan targets... ({len(enabled_detectors)} detectors)'
        })

        # Prepare targets list
        targets = [target] if isinstance(target, str) else target

        # Optional: Vuln pre-scan enumeration (subfinder/amass) BEFORE running detectors.
        pre_scan: Dict[str, Any] = {}
        try:
            if not scan_category and getattr(scan, 'scan_category', None):
                scan_category = getattr(scan.scan_category, 'name', None)
        except Exception:
            pass

        use_subfinder = bool(options.get('use_subfinder', False))
        use_amass = bool(options.get('use_amass', False))

        if str(scan_category or '').lower() == 'vuln' and (use_subfinder or use_amass):
            domain = _extract_domain_from_target(target)
            scheme = _derive_scheme_from_target(target)
            pre_scan = {
                'category': 'vuln',
                'domain': domain,
                'requested': {
                    'subfinder': use_subfinder,
                    'amass': use_amass,
                },
                'tools': {},
                'subdomains': [],
            }

            if domain:
                scan.progress = 15
                scan.current_step = 'Vuln pre-scan: enumerating subdomains...'
                scan.save(update_fields=['progress', 'current_step'])
                send_scan_update(scan_id, {
                    'progress': 15,
                    'current_step': 'Vuln pre-scan: enumerating subdomains...'
                })

                discovered: List[str] = []

                if use_subfinder:
                    scan.current_step = 'Vuln pre-scan: running subfinder...'
                    scan.save(update_fields=['current_step'])
                    send_scan_update(scan_id, {'current_step': 'Vuln pre-scan: running subfinder...'})
                    res = _run_external_lines(['subfinder', '-d', domain, '-silent'], timeout_seconds=180)
                    pre_scan['tools']['subfinder'] = {
                        'ok': res.get('ok', False),
                        'error': res.get('error') if not res.get('ok') else None,
                        'returncode': res.get('returncode'),
                        'stderr': res.get('stderr'),
                        'count': len(res.get('lines') or []),
                    }
                    discovered.extend(res.get('lines') or [])

                if use_amass:
                    scan.current_step = 'Vuln pre-scan: running amass (passive)...'
                    scan.save(update_fields=['current_step'])
                    send_scan_update(scan_id, {'current_step': 'Vuln pre-scan: running amass (passive)...'})
                    res = _run_external_lines(['amass', 'enum', '-passive', '-d', domain], timeout_seconds=240)
                    pre_scan['tools']['amass'] = {
                        'ok': res.get('ok', False),
                        'error': res.get('error') if not res.get('ok') else None,
                        'returncode': res.get('returncode'),
                        'stderr': res.get('stderr'),
                        'count': len(res.get('lines') or []),
                    }
                    discovered.extend(res.get('lines') or [])

                # Normalize, dedupe, and cap
                cleaned = []
                seen = set()
                for sd in discovered:
                    v = (sd or '').strip().lower()
                    if not v:
                        continue
                    if v in seen:
                        continue
                    seen.add(v)
                    cleaned.append(v)
                    if len(cleaned) >= 2000:
                        break

                pre_scan['subdomains'] = cleaned

                if cleaned:
                    # Expand scan targets using the same scheme as the original target.
                    expanded = [f'{scheme}://{sd}' for sd in cleaned]
                    # Keep original target first
                    targets = list(dict.fromkeys(([target] if isinstance(target, str) else list(targets)) + expanded))

                # Persist to scan.raw_results early so UI can fetch it while running.
                try:
                    raw = scan.raw_results
                    if isinstance(raw, str):
                        try:
                            raw = json.loads(raw) if raw else {}
                        except Exception:
                            raw = {}
                    if not isinstance(raw, dict):
                        raw = {}
                    raw['pre_scan'] = pre_scan
                    scan.raw_results = raw
                    scan.save(update_fields=['raw_results'])
                except Exception as exc:
                    logger.exception("Failed to persist pre_scan into raw_results for scan %s", scan_id)
                    pre_scan.setdefault('warnings', []).append({
                        'type': 'pre_scan_persist_failed',
                        'error_type': type(exc).__name__,
                        'error': str(exc)[:500],
                    })

                send_scan_update(scan_id, {
                    'current_step': f'Vuln pre-scan: discovered {len(cleaned)} subdomains',
                    'pre_scan': {
                        'domain': domain,
                        'subdomains_found': len(cleaned),
                        'tools': pre_scan.get('tools', {}),
                    }
                })
            else:
                pre_scan['error'] = 'invalid_domain'

        # Update progress
        scan.progress = 20
        scan.current_step = f'Starting {len(enabled_detectors)} detectors...'
        scan.save(update_fields=['progress', 'current_step'])
        send_scan_update(scan_id, {
            'progress': 20,
            'current_step': f'Starting {len(enabled_detectors)} detectors...',
            'total_detectors': len(enabled_detectors)
        })

        # Execute the scan
        logger.info(f"Executing scan with context: {scan_context}")
        logger.info(f"🎯 Running scan with {len(enabled_detectors)} detectors: {enabled_detectors}")

        progress_state: Dict[str, Any] = {
            'started_ts': time.time(),
            'total_urls': None,
            'urls_completed': 0,
            'current_detector': None,
            'current_url': None,
            'last_ws_ts': 0.0,
            'last_db_ts': 0.0,
        }

        def _format_eta(seconds: Optional[float]) -> Optional[str]:
            if seconds is None:
                return None
            try:
                seconds = float(seconds)
            except Exception:
                return None
            if seconds < 0:
                seconds = 0
            if seconds < 60:
                return f"{int(seconds)}s"
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            if minutes < 60:
                return f"{minutes}m {secs}s"
            hours = int(minutes // 60)
            minutes = int(minutes % 60)
            return f"{hours}h {minutes}m"

        def _compute_eta_seconds() -> Optional[float]:
            total_urls = progress_state.get('total_urls')
            urls_completed = progress_state.get('urls_completed') or 0
            if not total_urls or urls_completed <= 0:
                return None
            elapsed = time.time() - float(progress_state['started_ts'])
            if elapsed <= 0:
                return None
            rate = urls_completed / elapsed
            if rate <= 0:
                return None
            remaining = max(0, int(total_urls) - int(urls_completed))
            return remaining / rate

        def _progress_callback(payload: Dict[str, Any]) -> None:
            now = time.time()
            event = payload.get('event')

            if event == 'scan_targets':
                progress_state['total_urls'] = payload.get('total_urls')

            if event == 'detector_start':
                progress_state['current_detector'] = payload.get('detector')
                progress_state['current_url'] = payload.get('url')

            if event == 'url_complete':
                progress_state['urls_completed'] = (
                    payload.get('urls_completed')
                    or progress_state.get('urls_completed', 0)
                )
                progress_state['total_urls'] = payload.get('total_urls') or progress_state.get('total_urls')

            total_urls = progress_state.get('total_urls')
            urls_completed = progress_state.get('urls_completed') or 0
            eta_seconds = _compute_eta_seconds()
            eta_human = _format_eta(eta_seconds)

            # Map scanner loop into the main progress range [20..70]
            scan_progress = 20
            if total_urls:
                try:
                    frac = float(urls_completed) / float(total_urls)
                except Exception:
                    frac = 0.0
                frac = min(1.0, max(0.0, frac))
                scan_progress = 20 + int(round(frac * 50))

            current_detector = progress_state.get('current_detector')
            current_url = progress_state.get('current_url')

            # Build a user-facing step string (also used by clients that only read the DB).
            step_bits = ["Scanning"]
            if current_detector:
                step_bits.append(f"detector={current_detector}")
            if current_url:
                step_bits.append(f"url={current_url}")
            if eta_human:
                step_bits.append(f"ETA {eta_human}")
            current_step = ": ".join([step_bits[0], ", ".join(step_bits[1:])]) if len(step_bits) > 1 else "Scanning..."

            ws_due = (now - float(progress_state.get('last_ws_ts') or 0.0)) >= 0.5
            db_due = (now - float(progress_state.get('last_db_ts') or 0.0)) >= 2.0
            force = event in {'url_complete'}

            if force or ws_due:
                send_scan_update(scan_id, {
                    'status': 'running',
                    'progress': scan_progress,
                    'current_step': current_step,
                    'current_detector': current_detector,
                    'current_url': current_url,
                    'urls_completed': urls_completed,
                    'total_urls': total_urls,
                    'eta_seconds': eta_seconds,
                })
                progress_state['last_ws_ts'] = now

            if force or db_due:
                try:
                    scan.progress = scan_progress
                    scan.current_step = current_step
                    scan.save(update_fields=['progress', 'current_step'])
                except Exception:
                    logger.debug("Failed to persist progress update for scan %s", scan_id)
                progress_state['last_db_ts'] = now

        executed_detectors: List[Dict[str, Any]] = []
        skipped_detectors: List[Dict[str, Any]] = []

        results, metadata = scanner.run_scan(
            targets=targets,
            concurrency=scan_context['concurrency'],
            timeout=scan_context['timeout'],
            per_host_rate=scan_context['per_host_rate'],
            allow_destructive=scan_context['allow_destructive'],
            output_dir=scan_context['output_dir'],
            auto_confirm=scan_context['auto_confirm'],
            bypass_cloudflare=scan_context['bypass_cloudflare'],
            enable_forbidden_probe=scan_context['enable_forbidden_probe'],
            scan_mode=scan_context['scan_mode'],
            user_tier=user_tier,
            enabled_detectors=enabled_detectors,  # Pass as direct parameter
            extra_context={
                'celery_task_id': self.request.id,
                'job_id': scan_id,
                'enabled_detectors': enabled_detectors,  # Also keep in extra_context for compatibility
                'run_all_selected_detectors': bool(scan_context.get('run_all_selected_detectors', False)),
                '_executed_detectors': executed_detectors,
                '_skipped_detectors': skipped_detectors,
                '_progress_callback': _progress_callback,
                # pass-through options used by optional detectors
                'nuclei_templates': nuclei_templates,
                'nuclei_severity': nuclei_severity,
                'cve_db_path': cve_db_path,
            },
        )

        if isinstance(metadata, dict) and metadata.get('fatal_error'):
            raise RuntimeError(f"Scanner fatal_error: {metadata.get('fatal_error')}")

        # Update progress
        scan.progress = 70
        scan.current_step = 'Processing results...'
        scan.save(update_fields=['progress', 'current_step'])
        send_scan_update(scan_id, {
            'progress': 70,
            'current_step': 'Processing results...'
        })

        # Process results
        vulnerabilities_found = 0
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }

        # Count vulnerabilities by severity
        # Each result is already a single vulnerability finding
        for result in results:
            # Check if result has issues array (old format) or is direct finding (new format)
            issues = result.get('issues', [])
            if issues:
                # Old format with issues array
                vulnerabilities_found += len(issues)
                for issue in issues:
                    severity = issue.get('severity', 'info').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    else:
                        severity_counts['info'] += 1
            else:
                # New format - result is direct finding
                vulnerabilities_found += 1
                severity = result.get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts['info'] += 1

        # Update progress
        scan.progress = 85
        scan.current_step = 'Generating report...'
        scan.save(update_fields=['progress', 'current_step'])
        send_scan_update(scan_id, {
            'progress': 85,
            'current_step': 'Generating report...',
            'vulnerabilities_found': vulnerabilities_found,
            'severity_counts': severity_counts
        })

        # Generate report
        report_path = f'reports/scan_{scan_id}/report.json'
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        report_data = {
            'scan_id': scan_id,
            'target': target,
            'scan_category': scan_category,
            'scan_type': scan_type,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': timezone.now().isoformat(),
            'vulnerabilities_found': vulnerabilities_found,
            'severity_counts': severity_counts,
            'pre_scan': pre_scan,
            'execution': {
                'executed_detectors': executed_detectors,
                'skipped_detectors': skipped_detectors,
            },
            'findings': [],
            'results': results,
            'metadata': metadata,
        }

        # Extract and flatten findings from results
        for result in results:
            # Check if result has issues array (old format) or is direct finding (new format)
            issues = result.get('issues', [])
            if issues:
                # Old format with issues array
                for issue in issues:
                    finding = {
                        'type': issue.get('type', 'Unknown'),
                        'severity': issue.get('severity', 'low'),
                        'url': issue.get('url', result.get('url', '')),
                        'detector': issue.get('detector', 'unknown'),
                        'description': issue.get('description', ''),
                        'evidence': issue.get('evidence', ''),
                        'payload': issue.get('payload', ''),
                        'status': issue.get('status', None),
                        'response_time': issue.get('response_time', None),
                        'request_headers': issue.get('request_headers', {}),
                        'response_headers': issue.get('response_headers', {}),
                    }
                    report_data['findings'].append(finding)
            else:
                # New format - result is direct finding
                finding = {
                    'type': result.get('type', 'Unknown'),
                    'severity': result.get('severity', 'low'),
                    'url': result.get('url', ''),
                    'detector': result.get('detector', 'unknown'),
                    'description': result.get('description', ''),
                    'evidence': result.get('evidence', ''),
                    'payload': result.get('payload', ''),
                    'status': result.get('status', None),
                    'response_time': result.get('response_time', None),
                    'request_headers': result.get('request_headers', {}),
                    'response_headers': result.get('response_headers', {}),
                }
                report_data['findings'].append(finding)

        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        # Update scan with results
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.expires_at = scan.calculate_expiration()
        scan.report_path = report_path
        scan.raw_results = report_data
        scan.vulnerabilities_found = vulnerabilities_found
        scan.severity_counts = severity_counts
        scan.progress = 95
        scan.current_step = 'Storing findings...'
        scan.save(update_fields=[
            'status', 'completed_at', 'expires_at', 'report_path', 'raw_results',
            'vulnerabilities_found', 'severity_counts',
            'progress', 'current_step'
        ])

        # Parse and store individual findings in database
        findings_count = scan.parse_and_store_findings()
        logger.info(f"Stored {findings_count} findings in database for scan {scan_id}")

        # Fire integrations (best-effort)
        try:
            from users.integration_service import trigger_scan_event

            trigger_scan_event(
                scan=scan,
                event_type='scan_completed',
                extra={"findings_count": findings_count},
            )
            if vulnerabilities_found > 0:
                trigger_scan_event(
                    scan=scan,
                    event_type='vulnerability_found',
                    extra={"findings_count": findings_count},
                )
            if (severity_counts or {}).get('critical', 0) > 0:
                trigger_scan_event(
                    scan=scan,
                    event_type='critical_vulnerability',
                    extra={"findings_count": findings_count},
                )
        except Exception:
            logger.exception("Failed triggering integrations for scan %s", scan_id)

        # Update progress to completed
        scan.progress = 100
        scan.current_step = 'Scan completed'
        scan.save(update_fields=['progress', 'current_step'])

        # Send completion update via WebSocket
        send_scan_complete(scan_id, {
            'status': 'completed',
            'progress': 100,
            'completed_at': scan.completed_at.isoformat(),
            'vulnerabilities_found': vulnerabilities_found,
            'severity_counts': severity_counts,
            'report_path': report_path
        })

        logger.info(f"Scan {scan_id} completed successfully. Found {vulnerabilities_found} vulnerabilities.")

        # Audit (best-effort)
        try:
            from users.scan_audit import create_scan_audit_log_system

            create_scan_audit_log_system(
                scan=scan,
                action='scan_completed',
                metadata={
                    'source': 'celery:execute_scan_task',
                    'celery_task_id': getattr(self.request, 'id', None),
                    'findings_count': findings_count,
                    'enabled_detectors': enabled_detectors,
                },
            )
        except Exception:
            logger.exception("Failed writing audit log for completed scan %s", scan_id)

        return {
            'scan_id': scan_id,
            'status': 'completed',
            'vulnerabilities_found': vulnerabilities_found,
            'severity_counts': severity_counts,
            'report_path': report_path,
        }

    except Scan.DoesNotExist:
        error_msg = f"Scan with ID {scan_id} not found"
        logger.error(error_msg)
        return {'scan_id': scan_id, 'status': 'failed', 'error': error_msg}

    except Exception as e:
        def _one_line(text: str) -> str:
            if not text:
                return ''
            # Keep it single-line and reasonably short for UX/DB fields.
            return ' '.join(str(text).replace('\r', '\n').split('\n')).strip()

        full_error = str(e) if e is not None else ''
        short_error = _one_line(full_error) or type(e).__name__
        # current_step max_length=200 (model); keep room for prefix.
        short_error = short_error[:180]

        error_msg = f"Scan {scan_id} failed: {short_error}"
        logger.exception(error_msg)

        # Update scan status to failed
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.expires_at = scan.calculate_expiration()
            scan.progress = 0
            scan.current_step = f'Error: {short_error}'
            scan.raw_results = {
                'status': 'failed',
                'error': full_error,
                'error_short': short_error,
                'error_type': type(e).__name__,
            }
            scan.save(update_fields=['status', 'completed_at', 'expires_at', 'progress', 'current_step', 'raw_results'])

            # Audit (best-effort)
            try:
                from users.scan_audit import create_scan_audit_log_system

                create_scan_audit_log_system(
                    scan=scan,
                    action='scan_failed',
                    error_message=str(e),
                    metadata={
                        'source': 'celery:execute_scan_task',
                        'celery_task_id': getattr(self.request, 'id', None),
                    },
                )
            except Exception:
                logger.exception("Failed writing audit log for failed scan %s", scan_id)

            # Fire integrations (best-effort)
            try:
                from users.integration_service import trigger_scan_event

                trigger_scan_event(
                    scan=scan,
                    event_type='scan_failed',
                    extra={"error": str(e)},
                )
            except Exception:
                logger.exception("Failed triggering integrations for failed scan %s", scan_id)

            # Send error via WebSocket
            send_scan_error(scan_id, {
                'status': 'failed',
                'error': short_error,
                'completed_at': scan.completed_at.isoformat()
            })
        except Exception as save_error:
            logger.error(f"Failed to update scan status: {save_error}")

        # Retry the task if retries are available
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying scan {scan_id} (attempt {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(exc=e, countdown=60)

        return {
            'scan_id': scan_id,
            'status': 'failed',
            'error': str(e),
        }


@shared_task
def cancel_scan_task(scan_id: int) -> Dict[str, Any]:
    """
    Cancel a running scan.

    Args:
        scan_id: The ID of the Scan model instance to cancel

    Returns:
        Dictionary with cancellation status
    """
    from scans.models import Scan

    try:
        scan = Scan.objects.get(id=scan_id)

        if scan.status not in ['running', 'pending']:
            return {
                'scan_id': scan_id,
                'status': 'already_stopped',
                'message': f'Scan is already {scan.status}'
            }

        # Try to revoke the Celery task
        # Note: This requires the task_id to be stored, which we'll add to the model

        # Update scan status
        scan.status = 'stopped'
        scan.completed_at = timezone.now()
        scan.expires_at = scan.calculate_expiration()
        scan.save(update_fields=['status', 'completed_at', 'expires_at'])

        # Audit (best-effort)
        try:
            from users.scan_audit import create_scan_audit_log_system

            create_scan_audit_log_system(
                scan=scan,
                action='scan_cancelled',
                metadata={
                    'source': 'celery:cancel_scan_task',
                },
            )
        except Exception:
            logger.exception("Failed writing audit log for cancelled scan %s", scan_id)

        logger.info(f"Scan {scan_id} cancelled successfully")

        return {
            'scan_id': scan_id,
            'status': 'stopped',
            'message': 'Scan cancelled successfully'
        }

    except Scan.DoesNotExist:
        error_msg = f"Scan with ID {scan_id} not found"
        logger.error(error_msg)
        return {'scan_id': scan_id, 'status': 'error', 'error': error_msg}

    except Exception as e:
        error_msg = f"Failed to cancel scan {scan_id}: {str(e)}"
        logger.exception(error_msg)
        return {'scan_id': scan_id, 'status': 'error', 'error': str(e)}


@shared_task
def cleanup_old_scans_task(days: int = 30) -> Dict[str, Any]:
    """
    Clean up old scan reports and data.

    Args:
        days: Delete scans older than this many days

    Returns:
        Dictionary with cleanup statistics
    """
    from scans.models import Scan
    from datetime import timedelta
    import shutil

    try:
        cutoff_date = timezone.now() - timedelta(days=days)
        old_scans = Scan.objects.filter(created_at__lt=cutoff_date)

        deleted_count = 0
        deleted_size = 0

        for scan in old_scans:
            # Delete report files
            if scan.report_path and os.path.exists(scan.report_path):
                report_dir = os.path.dirname(scan.report_path)
                if os.path.exists(report_dir):
                    # Calculate size before deletion
                    for root, dirs, files in os.walk(report_dir):
                        for f in files:
                            fp = os.path.join(root, f)
                            deleted_size += os.path.getsize(fp)

                    shutil.rmtree(report_dir)

            # Delete scan record
            scan.delete()
            deleted_count += 1

        logger.info(f"Cleaned up {deleted_count} old scans, freed {deleted_size / (1024 * 1024):.2f} MB")

        return {
            'status': 'success',
            'deleted_count': deleted_count,
            'deleted_size_mb': deleted_size / (1024 * 1024),
            'cutoff_date': cutoff_date.isoformat(),
        }

    except Exception as e:
        error_msg = f"Failed to cleanup old scans: {str(e)}"
        logger.exception(error_msg)
        return {'status': 'error', 'error': str(e)}


@shared_task
def cleanup_expired_scans_task() -> Dict[str, Any]:
    """Delete expired scans + associated files.

    Uses Scan.expires_at; falls back to calculating expires_at for completed scans
    that don't have it set yet.
    """
    from scans.models import Scan

    now = timezone.now()

    # Backfill expires_at for completed scans that are missing it (best-effort).
    backfilled = 0
    for scan in Scan.objects.filter(expires_at__isnull=True, completed_at__isnull=False).iterator(chunk_size=200):
        try:
            scan.expires_at = scan.calculate_expiration()
            scan.save(update_fields=['expires_at'])
            backfilled += 1
        except Exception:
            logger.exception("Failed backfilling expires_at for scan %s", getattr(scan, 'id', None))

    expired_qs = Scan.objects.filter(expires_at__isnull=False, expires_at__lt=now)
    expired_count = expired_qs.count()

    deleted = 0
    for scan in expired_qs.iterator(chunk_size=200):
        try:
            try:
                scan.delete_files()
            except Exception:
                logger.exception("Failed deleting files for expired scan %s", scan.id)
            scan.delete()
            deleted += 1
        except Exception:
            logger.exception("Failed deleting expired scan %s", getattr(scan, 'id', None))

    return {
        'status': 'success',
        'backfilled': backfilled,
        'expired_found': expired_count,
        'deleted': deleted,
        'timestamp': now.isoformat(),
    }


@shared_task
def cleanup_stuck_scans_task(pending_minutes: int = 30, running_minutes: int = 120) -> Dict[str, Any]:
    """Mark scans as failed if they appear stuck (e.g., worker/broker down).

    - pending too long (never transitioned to running)
    - running too long (exceeded expected runtime)
    """
    from datetime import timedelta
    from scans.models import Scan

    now = timezone.now()
    pending_cutoff = now - timedelta(minutes=pending_minutes)
    running_cutoff = now - timedelta(minutes=running_minutes)

    stuck_pending = Scan.objects.filter(status='pending', created_at__lt=pending_cutoff)
    stuck_running = Scan.objects.filter(status='running', started_at__lt=running_cutoff)

    updated = 0

    for scan in list(stuck_pending) + list(stuck_running):
        try:
            scan.status = 'failed'
            scan.completed_at = now
            scan.current_step = 'Marked failed by cleanup (stuck scan)'
            scan.save(update_fields=['status', 'completed_at', 'current_step'])
            updated += 1

            try:
                from users.scan_audit import create_scan_audit_log_system

                create_scan_audit_log_system(
                    scan=scan,
                    action='scan_failed',
                    error_message='stuck_scan_cleanup',
                    metadata={
                        'source': 'celery:cleanup_stuck_scans_task',
                        'previous_status': 'pending' if scan in stuck_pending else 'running',
                    },
                )
            except Exception:
                logger.exception("Failed writing audit for stuck scan %s", scan.id)
        except Exception:
            logger.exception("Failed cleaning up stuck scan %s", getattr(scan, 'id', None))

    return {
        'status': 'success',
        'updated': updated,
        'pending_checked': stuck_pending.count(),
        'running_checked': stuck_running.count(),
        'pending_cutoff': pending_cutoff.isoformat(),
        'running_cutoff': running_cutoff.isoformat(),
    }


# ── OWASP ZAP scan task ───────────────────────────────────────────────────────

@shared_task(bind=True, ignore_result=True, time_limit=2100, soft_time_limit=1980)
def run_zap_scan_task(
    self,
    scan_id: int,
    target: str,
    scan_mode: str = "baseline",
    openapi_url: str = "",
    image: str = "",
) -> None:
    """
    Celery task — run an OWASP ZAP scan and persist findings.

    Args:
        scan_id   : DB primary key of an existing Scan record.
        target    : Target URL.
        scan_mode : 'baseline' | 'full' | 'api'
        openapi_url: OpenAPI spec URL (for mode='api').
        image     : Docker image override.
    """
    from scans.models import Scan, Vulnerability
    from scans.websocket_utils import send_scan_update, send_scan_complete, send_scan_error
    from scans.zap_service import run_zap_scan

    logger.info("run_zap_scan_task: starting scan_id=%d target=%s mode=%s", scan_id, target, scan_mode)

    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        logger.error("run_zap_scan_task: Scan %d not found", scan_id)
        return

    scan.status = "running"
    scan.started_at = timezone.now()
    scan.progress = 0
    scan.current_step = "ZAP scan initialising…"
    scan.save(update_fields=["status", "started_at", "progress", "current_step"])
    send_scan_update(scan_id, {
        "status": "running",
        "progress": 0,
        "current_step": "ZAP scan initialising…",
    })

    def _on_progress(pct: int, msg: str) -> None:
        scan.progress = pct
        scan.current_step = msg
        scan.save(update_fields=["progress", "current_step"])
        send_scan_update(scan_id, {"status": "running", "progress": pct, "current_step": msg})

    try:
        findings = run_zap_scan(
            scan_db_id=scan_id,
            target=target,
            scan_mode=scan_mode,
            progress_callback=_on_progress,
            openapi_url=openapi_url,
            image=image,
        )

        # Persist findings
        vulns_to_create = []
        severity_counts: Dict[str, int] = {}
        for f in findings:
            severity = f.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            vulns_to_create.append(Vulnerability(
                scan=scan,
                title=str(f.get("type", "ZAP Finding"))[:255],
                description=str(f.get("description", ""))[:2000],
                severity=severity,
                confidence=int(f.get("confidence", 50)),
                url=str(f.get("url", ""))[:500],
                payload=str(f.get("payload", ""))[:500],
                evidence=str(f.get("evidence", ""))[:1000],
                detector="zap",
                remediation=str(f.get("remediation", ""))[:1000],
            ))

        if vulns_to_create:
            Vulnerability.objects.bulk_create(vulns_to_create, batch_size=200)

        scan.status = "completed"
        scan.completed_at = timezone.now()
        scan.progress = 100
        scan.current_step = f"ZAP scan complete — {len(vulns_to_create)} findings"
        scan.vulnerabilities_found = len(vulns_to_create)
        scan.severity_counts = severity_counts
        scan.save(update_fields=[
            "status", "completed_at", "progress", "current_step",
            "vulnerabilities_found", "severity_counts",
        ])

        send_scan_complete(scan_id, {
            "status": "completed",
            "progress": 100,
            "vulnerabilities_found": len(vulns_to_create),
            "severity_counts": severity_counts,
        })
        logger.info(
            "run_zap_scan_task: scan_id=%d finished, %d findings",
            scan_id, len(vulns_to_create),
        )

    except Exception as exc:
        logger.exception("run_zap_scan_task: scan_id=%d failed: %s", scan_id, exc)
        scan.status = "failed"
        scan.completed_at = timezone.now()
        scan.current_step = f"ZAP scan failed: {str(exc)[:200]}"
        scan.save(update_fields=["status", "completed_at", "current_step"])
        send_scan_error(scan_id, {"error": str(exc)[:500]})


# ── Mobile app scan task ──────────────────────────────────────────────────────

@shared_task(bind=True, ignore_result=True, time_limit=600, soft_time_limit=540)
def run_mobile_scan_task(
    self,
    scan_id: int,
    file_path: str,
    platform: str,
    app_name: str = "",
) -> None:
    """
    Celery task — run a static mobile app scan (APK/IPA) and persist findings.

    Args:
        scan_id   : DB primary key of an existing Scan record.
        file_path : Absolute path to the uploaded APK or IPA file.
        platform  : 'android' | 'ios'
        app_name  : Human-readable app name for display.
    """
    import os
    from scans.models import Scan, Vulnerability
    from scans.websocket_utils import send_scan_update, send_scan_complete, send_scan_error
    from mobile_scanner.mobile_scan_service import run_mobile_scan

    logger.info(
        "run_mobile_scan_task: scan_id=%d platform=%s file=%s",
        scan_id, platform, file_path,
    )

    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        logger.error("run_mobile_scan_task: Scan %d not found", scan_id)
        return

    scan.status = "running"
    scan.started_at = timezone.now()
    scan.progress = 0
    scan.current_step = "Mobile scan initialising…"
    scan.save(update_fields=["status", "started_at", "progress", "current_step"])
    send_scan_update(scan_id, {"status": "running", "progress": 0, "current_step": "Mobile scan initialising…"})

    def _on_progress(pct: int, msg: str) -> None:
        scan.progress = pct
        scan.current_step = msg
        scan.save(update_fields=["progress", "current_step"])
        send_scan_update(scan_id, {"status": "running", "progress": pct, "current_step": msg})

    try:
        findings = run_mobile_scan(
            file_path=file_path,
            platform=platform,
            progress_callback=_on_progress,
        )

        # Persist findings
        vulns_to_create = []
        severity_counts: Dict[str, int] = {}
        for f in findings:
            severity = f.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            vuln = Vulnerability(
                scan=scan,
                title=str(f.get("title", "Mobile Finding"))[:255],
                description=str(f.get("description", ""))[:2000],
                severity=severity,
                confidence=int(f.get("confidence", 50)),
                url=str(f.get("url", ""))[:500],
                payload=str(f.get("payload", ""))[:500],
                evidence=str(f.get("evidence", ""))[:1000],
                detector=str(f.get("detector", "mobile_scanner")),
                raw_data=f.get("raw_data", {}),
            )
            if f.get("cvss_score") is not None:
                vuln.cvss_score = f["cvss_score"]
            if f.get("remediation"):
                vuln.notes = str(f["remediation"])[:1000]
            vulns_to_create.append(vuln)

        if vulns_to_create:
            Vulnerability.objects.bulk_create(vulns_to_create, batch_size=200)

        scan.status = "completed"
        scan.completed_at = timezone.now()
        scan.progress = 100
        scan.current_step = f"Scan complete — {len(vulns_to_create)} findings"
        scan.vulnerabilities_found = len(vulns_to_create)
        scan.severity_counts = severity_counts
        scan.save(update_fields=[
            "status", "completed_at", "progress", "current_step",
            "vulnerabilities_found", "severity_counts",
        ])

        send_scan_complete(scan_id, {
            "status": "completed",
            "progress": 100,
            "vulnerabilities_found": len(vulns_to_create),
            "severity_counts": severity_counts,
        })
        logger.info(
            "run_mobile_scan_task: scan_id=%d done, %d findings",
            scan_id, len(vulns_to_create),
        )

    except Exception as exc:
        logger.exception("run_mobile_scan_task: scan_id=%d failed: %s", scan_id, exc)
        scan.status = "failed"
        scan.completed_at = timezone.now()
        scan.current_step = f"Mobile scan failed: {str(exc)[:200]}"
        scan.save(update_fields=["status", "completed_at", "current_step"])
        send_scan_error(scan_id, {"error": str(exc)[:500]})

    finally:
        # Clean up uploaded file after scan (success or failure)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
        except OSError as exc:
            logger.warning("run_mobile_scan_task: could not delete %s: %s", file_path, exc)

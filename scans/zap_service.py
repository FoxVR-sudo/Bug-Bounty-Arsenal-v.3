"""
scans/zap_service.py

OWASP ZAP integration — manages Docker container lifecycle and translates
ZAP JSON alerts into the project's standard Vulnerability format.

Requirements:
  - Docker must be installed and accessible by the server process.
  - Set ZAP_ENABLED=True in .env to enable this component.
  - Set ZAP_API_KEY to a random secret string (e.g. openssl rand -hex 16).

Scan modes:
  - baseline  : Passive scan only — safe for production targets.
  - full       : Active scan (SQL injection, XSS, etc.) — use on test environments only.
  - api        : OpenAPI/Swagger-driven scan — provide openapi_url in options.
"""

from __future__ import annotations

import logging
import secrets
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests as _requests

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_DEFAULT_IMAGE = "zaproxy/zap-stable"
_ZAP_CONTAINER_PREFIX = "bugbounty_zap_"
_ZAP_STARTUP_TIMEOUT = 90   # seconds to wait for ZAP daemon to be ready
_ZAP_SCAN_TIMEOUT = 1800    # 30 min hard timeout for the whole scan
_POLL_INTERVAL = 5           # seconds between progress polls

# Severity mapping: ZAP risk level → our severity
_RISK_MAP = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}

# Confidence mapping: ZAP confidence → int 0-100
_CONFIDENCE_MAP = {
    "3": 85,   # Confirmed
    "2": 70,   # Medium
    "1": 50,   # Low
    "0": 30,   # False Positive (ZAP still reports, we keep low confidence)
    "Confirmed": 85,
    "Medium": 70,
    "Low": 50,
    "False Positive": 30,
}


# ── Docker helpers ─────────────────────────────────────────────────────────────

def _free_port() -> int:
    """Find a free localhost port for the ZAP daemon."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _pull_image_if_needed(image: str) -> None:
    """Pull ZAP Docker image if not already present (best-effort)."""
    try:
        check = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if check.returncode == 0:
            return  # already present
        logger.info("zap_service: pulling Docker image %s (first use)…", image)
        subprocess.run(
            ["docker", "pull", image],
            capture_output=False,
            timeout=300,
            check=True,
        )
    except Exception as exc:
        logger.warning("zap_service: could not pull %s: %s", image, exc)


def _start_zap_container(
    scan_id: int,
    api_key: str,
    port: int,
    image: str,
) -> str:
    """Start a ZAP daemon container.  Returns the container ID."""
    container_name = f"{_ZAP_CONTAINER_PREFIX}{scan_id}"
    cmd = [
        "docker", "run",
        "-d",
        "--rm",
        "--name", container_name,
        "-p", f"127.0.0.1:{port}:8080",
        image,
        "zap.sh",
        "-daemon",
        "-host", "0.0.0.0",
        "-port", "8080",
        "-config", f"api.key={api_key}",
        # Allow calls from any address (we always bind to localhost only)
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.enabled=true",
        # Disable telemetry
        "-config", "api.disablekey=false",
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return result.stdout.strip()


def _stop_zap_container(scan_id: int) -> None:
    """Stop and remove the ZAP container for a scan (best-effort)."""
    container_name = f"{_ZAP_CONTAINER_PREFIX}{scan_id}"
    try:
        subprocess.run(
            ["docker", "stop", container_name],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:
        logger.debug("zap_service: error stopping container %s: %s", container_name, exc)


# ── ZAP API client ─────────────────────────────────────────────────────────────

class ZapClient:
    """Minimal synchronous wrapper around the ZAP JSON API."""

    def __init__(self, host: str, port: int, api_key: str):
        self._base = f"http://{host}:{port}/JSON"
        self._key = api_key
        self._session = _requests.Session()
        self._session.headers["X-ZAP-API-Key"] = api_key

    def _get(self, path: str, params: Optional[Dict] = None) -> Dict:
        url = f"{self._base}{path}"
        resp = self._session.get(url, params=params or {}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def version(self) -> str:
        return self._get("/core/view/version/")["version"]

    def access_url(self, target: str) -> None:
        self._get("/core/action/accessUrl/", {"url": target})

    def spider_scan(self, target: str) -> str:
        data = self._get("/spider/action/scan/", {"url": target, "maxChildren": "10"})
        return str(data.get("scan", "0"))

    def spider_status(self, scan_id: str) -> int:
        data = self._get("/spider/view/status/", {"scanId": scan_id})
        return int(data.get("status", 0))

    def active_scan(self, target: str) -> str:
        data = self._get("/ascan/action/scan/", {"url": target, "recurse": "true"})
        return str(data.get("scan", "0"))

    def active_scan_status(self, scan_id: str) -> int:
        data = self._get("/ascan/view/status/", {"scanId": scan_id})
        return int(data.get("status", 0))

    def passive_scan_records_to_scan(self) -> int:
        data = self._get("/pscan/view/recordsToScan/")
        return int(data.get("recordsToScan", 0))

    def alerts(self, base_url: str = "") -> List[Dict]:
        params = {"baseurl": base_url} if base_url else {}
        data = self._get("/core/view/alerts/", params)
        return data.get("alerts", [])

    def openapi_import(self, openapi_url: str, target: str) -> None:
        self._get(
            "/openapi/action/importUrl/",
            {"url": openapi_url, "hostOverride": target},
        )

    def shutdown(self) -> None:
        try:
            self._get("/core/action/shutdown/")
        except Exception:
            pass


# ── Waiting for ZAP daemon ─────────────────────────────────────────────────────

def _wait_for_zap(host: str, port: int, api_key: str, timeout: int) -> ZapClient:
    """Poll until ZAP daemon responds, then return a connected client."""
    client = ZapClient(host, port, api_key)
    deadline = time.monotonic() + timeout
    last_exc: Exception = RuntimeError("ZAP did not start in time")
    while time.monotonic() < deadline:
        try:
            client.version()
            logger.info("zap_service: ZAP daemon ready on port %d", port)
            return client
        except Exception as exc:
            last_exc = exc
            time.sleep(2)
    raise TimeoutError(f"ZAP daemon did not start within {timeout}s: {last_exc}")


# ── Alert normalisation ────────────────────────────────────────────────────────

def _normalise_alert(alert: Dict, scan_id_db: int) -> Dict[str, Any]:
    """Convert a ZAP alert dict to the project's finding format."""
    risk_str = str(alert.get("risk", "0"))
    conf_str = str(alert.get("confidence", "1"))
    severity = _RISK_MAP.get(risk_str, "info")
    confidence = _CONFIDENCE_MAP.get(conf_str, 50)

    name = alert.get("name") or alert.get("alert") or "ZAP Finding"
    url = alert.get("url") or ""
    description = alert.get("description") or ""
    solution = alert.get("solution") or ""
    evidence = alert.get("evidence") or ""
    cwe_id = alert.get("cweid") or ""
    wasc_id = alert.get("wascid") or ""
    plugin_id = alert.get("pluginId") or alert.get("alertRef") or ""
    other = alert.get("other") or ""

    extra_info = []
    if solution:
        extra_info.append(f"Solution: {solution}")
    if cwe_id:
        extra_info.append(f"CWE-{cwe_id}")
    if wasc_id:
        extra_info.append(f"WASC-{wasc_id}")
    if other:
        extra_info.append(other[:200])

    return {
        "type": name,
        "severity": severity,
        "confidence": confidence,
        "url": url,
        "description": description,
        "evidence": evidence[:500] if evidence else "; ".join(extra_info)[:500],
        "payload": alert.get("param") or alert.get("attack") or "",
        "status_code": None,
        "detector": "zap",
        "source": "OWASP ZAP",
        "plugin_id": plugin_id,
        "remediation": solution[:500] if solution else "",
        "scan_id": scan_id_db,
    }


# ── Main scan runner ───────────────────────────────────────────────────────────

def run_zap_scan(
    scan_db_id: int,
    target: str,
    scan_mode: str = "baseline",
    progress_callback=None,
    openapi_url: str = "",
    image: str = "",
) -> List[Dict[str, Any]]:
    """
    Run a ZAP scan against *target* and return normalised findings.

    Args:
        scan_db_id    : The DB primary key of the Scan record.
        target        : Target URL (must include scheme, e.g. https://example.com).
        scan_mode     : 'baseline' | 'full' | 'api'
        progress_callback : Optional callable(percent: int, message: str).
        openapi_url   : OpenAPI spec URL (required for mode='api').
        image         : Docker image override (default: zaproxy/zap-stable).

    Returns:
        List of normalised finding dicts.

    Raises:
        RuntimeError  : If Docker is unavailable or ZAP fails to start.
    """
    from django.conf import settings

    if not getattr(settings, "ZAP_ENABLED", False):
        raise RuntimeError("ZAP_ENABLED is not set to True in settings/env.")

    if not _docker_available():
        raise RuntimeError(
            "Docker is not available. Install Docker and ensure the server process "
            "can run `docker` commands."
        )

    api_key = getattr(settings, "ZAP_API_KEY", None) or secrets.token_hex(16)
    zap_image = image or getattr(settings, "ZAP_DOCKER_IMAGE", _DEFAULT_IMAGE)

    # Ensure target has a scheme
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    def _progress(pct: int, msg: str) -> None:
        logger.info("zap_service [scan=%d]: %d%% — %s", scan_db_id, pct, msg)
        if progress_callback:
            progress_callback(pct, msg)

    port = _free_port()
    _progress(0, f"Pulling Docker image {zap_image}…")
    _pull_image_if_needed(zap_image)

    _progress(5, "Starting ZAP daemon container…")
    try:
        _start_zap_container(scan_db_id, api_key, port, zap_image)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Failed to start ZAP container: {exc.stderr}"
        ) from exc

    try:
        _progress(10, "Waiting for ZAP daemon to be ready…")
        client = _wait_for_zap("127.0.0.1", port, api_key, _ZAP_STARTUP_TIMEOUT)

        _progress(15, f"ZAP ready — starting {scan_mode} scan against {target}")

        if scan_mode == "api":
            # OpenAPI/Swagger import
            spec_url = openapi_url or target
            _progress(20, f"Importing OpenAPI spec from {spec_url}")
            client.openapi_import(spec_url, urlparse(target).netloc)

        elif scan_mode in ("baseline", "full"):
            # Spider first for better coverage
            _progress(20, "Running spider…")
            spider_id = client.spider_scan(target)
            deadline = time.monotonic() + _ZAP_SCAN_TIMEOUT
            while time.monotonic() < deadline:
                pct = client.spider_status(spider_id)
                _progress(20 + int(pct * 0.15), f"Spider: {pct}%")
                if pct >= 100:
                    break
                time.sleep(_POLL_INTERVAL)

        # Passive scan is always running (built-in to ZAP)
        _progress(35, "Waiting for passive scan to finish…")
        deadline = time.monotonic() + _ZAP_SCAN_TIMEOUT
        while time.monotonic() < deadline:
            remaining = client.passive_scan_records_to_scan()
            if remaining == 0:
                break
            _progress(35, f"Passive scan: {remaining} records remaining…")
            time.sleep(_POLL_INTERVAL)

        if scan_mode == "full":
            _progress(50, "Running active scan (this may take a while)…")
            ascan_id = client.active_scan(target)
            deadline = time.monotonic() + _ZAP_SCAN_TIMEOUT
            while time.monotonic() < deadline:
                pct = client.active_scan_status(ascan_id)
                _progress(50 + int(pct * 0.45), f"Active scan: {pct}%")
                if pct >= 100:
                    break
                time.sleep(_POLL_INTERVAL)

        _progress(95, "Collecting alerts…")
        raw_alerts = client.alerts(target)
        logger.info(
            "zap_service [scan=%d]: collected %d raw alerts",
            scan_db_id, len(raw_alerts),
        )

        findings = [_normalise_alert(a, scan_db_id) for a in raw_alerts]

        # Deduplicate: same (type, url, payload)
        seen: set = set()
        unique: List[Dict] = []
        for f in findings:
            key = (f["type"], f["url"], f.get("payload", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        _progress(100, f"ZAP scan complete — {len(unique)} unique findings")
        return unique

    finally:
        _stop_zap_container(scan_db_id)

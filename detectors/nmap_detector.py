"""detectors/nmap_detector.py

Nmap port/service/vulnerability scanner.

Reads scan options from context:
  nmap_preset  : "quick" | "service" | "scripts" | "vuln" | "full" | "custom"
  nmap_custom  : str  — extra flags appended after preset flags (or full command in custom mode)

Presets:
  quick   → -T4 --top-ports 100
  service → -sV -T4 --top-ports 1000              (default)
  scripts → -sV -sC -T4 --top-ports 1000
  vuln    → -sV --script=vuln -T4 --top-ports 1000
  full    → -sV -sC -T4 -p-                       (all ports, slow)
  custom  → only the flags from nmap_custom field

Output: findings per open port + script output findings.
Uses XML output for reliable parsing (-oX -).
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from urllib.parse import urlparse

from detectors.registry import register_active, DetectorSkip

logger = logging.getLogger(__name__)

_PRESET_FLAGS: Dict[str, List[str]] = {
    "quick":   ["-T4", "--top-ports", "100"],
    "service": ["-sV", "-T4", "--top-ports", "1000"],
    "scripts": ["-sV", "-sC", "-T4", "--top-ports", "1000"],
    "vuln":    ["-sV", "--script=vuln", "-T4", "--top-ports", "1000"],
    "full":    ["-sV", "-sC", "-T4", "-p-"],
}

# Service/port findings that map to higher severity
_HIGH_SEVERITY_PORTS = {21, 23, 25, 110, 143, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
_MEDIUM_SEVERITY_PORTS = {22, 80, 443, 8080, 8443, 8888}

_VULN_SCRIPT_RE = re.compile(
    r'(VULNERABLE|CVE-\d{4}-\d+|State:\s+VULNERABLE)', re.IGNORECASE
)


def _extract_host(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or url.split("/")[0]


def _parse_nmap_xml(xml_bytes: bytes, url: str) -> List[Dict[str, Any]]:
    """Parse nmap XML output into finding dicts."""
    findings: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        logger.warning("nmap_detector: XML parse error: %s", exc)
        return findings

    for host_el in root.findall(".//host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        addr_el = host_el.find("address")
        host_addr = addr_el.get("addr", "") if addr_el is not None else ""

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")

            service_el = port_el.find("service")
            service_name = ""
            service_product = ""
            service_version = ""
            if service_el is not None:
                service_name = service_el.get("name", "")
                service_product = service_el.get("product", "")
                service_version = service_el.get("version", "")

            service_str = " ".join(filter(None, [service_name, service_product, service_version])).strip()

            # Severity based on port
            if portid in _HIGH_SEVERITY_PORTS:
                severity = "high"
            elif portid in _MEDIUM_SEVERITY_PORTS:
                severity = "medium"
            else:
                severity = "info"

            findings.append({
                "type": "Open Port",
                "severity": severity,
                "url": url,
                "detector": "nmap_detector",
                "title": f"Open port {portid}/{protocol}" + (f" ({service_name})" if service_name else ""),
                "description": (
                    f"Port {portid}/{protocol} is open on {host_addr}. "
                    + (f"Service: {service_str}. " if service_str else "")
                    + ("This port is commonly associated with sensitive services." if severity == "high" else "")
                ),
                "evidence": f"host={host_addr} port={portid}/{protocol} service={service_str}",
                "confidence": "high",
                "category": "recon",
                "raw_data": {
                    "host": host_addr,
                    "port": portid,
                    "protocol": protocol,
                    "service": service_str,
                },
            })

            # Script output — look for vulnerability findings
            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                script_output = script_el.get("output", "")
                if not script_output:
                    continue
                if _VULN_SCRIPT_RE.search(script_output):
                    # Extract CVE if present
                    cve_match = re.search(r'CVE-\d{4}-\d+', script_output)
                    cve = cve_match.group(0) if cve_match else ""
                    findings.append({
                        "type": "Nmap Script Finding",
                        "severity": "high",
                        "url": url,
                        "detector": "nmap_detector",
                        "title": f"Vulnerability found by {script_id} on port {portid}",
                        "description": f"Nmap script '{script_id}' reported a vulnerability on port {portid}/{protocol}.",
                        "evidence": script_output[:800],
                        "confidence": "medium",
                        "category": "recon",
                        "raw_data": {
                            "host": host_addr,
                            "port": portid,
                            "protocol": protocol,
                            "script": script_id,
                            "cve": cve,
                        },
                    })

    return findings


@register_active
async def nmap_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run nmap scan against the target host."""
    # Run once per host per scan session
    host = _extract_host(url)
    if not host:
        raise DetectorSkip("cannot extract host from URL")

    cache_key = f"_nmap_done_{host}"
    if context.get(cache_key):
        raise DetectorSkip("already ran nmap for this host")
    context[cache_key] = True

    binary = shutil.which("nmap")
    if not binary:
        raise DetectorSkip("`nmap` binary not found in PATH")

    preset = str(context.get("nmap_preset", "service")).strip().lower()
    custom_flags_str = str(context.get("nmap_custom", "")).strip()

    # Build flag list
    if preset == "custom":
        if not custom_flags_str:
            raise DetectorSkip("nmap preset=custom but nmap_custom is empty")
        import shlex
        flag_list = shlex.split(custom_flags_str)
    else:
        flag_list = list(_PRESET_FLAGS.get(preset, _PRESET_FLAGS["service"]))
        if custom_flags_str:
            import shlex
            flag_list += shlex.split(custom_flags_str)

    # Security: strip dangerous output flags the user might inject
    _forbidden = {"-oN", "-oG", "-oA", "--script-updatedb", "--send-eth", "--send-ip", "-S", "--spoof-mac"}
    flag_list = [f for f in flag_list if f not in _forbidden]

    cmd = [binary] + flag_list + ["-oX", "-", host]
    logger.info("nmap_detector: running: %s", " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise DetectorSkip("nmap timed out after 600s")

    if proc.returncode not in (0, 1):
        err = (stderr or b"").decode("utf-8", errors="replace")[:400]
        raise DetectorSkip(f"nmap exited with code {proc.returncode}: {err}")

    xml_out = stdout or b""
    if not xml_out.strip():
        return []

    findings = _parse_nmap_xml(xml_out, url)
    logger.info("nmap_detector: %d findings for %s", len(findings), host)
    return findings

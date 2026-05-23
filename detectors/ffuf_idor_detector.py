"""detectors/ffuf_idor_detector.py

IDOR fuzzing via ffuf — replaces numeric ID parameters with FUZZ
and checks for differences in response (potential IDOR).
Only runs against URLs whose parameters look like object IDs.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

from detectors.registry import register_active, DetectorSkip

_ID_PARAM_RE = re.compile(
    r"(id|user_?id|account_?id|doc_?id|file_?id|order_?id|item_?id|post_?id|message_?id|ticket_?id)",
    re.IGNORECASE,
)
_NUMERIC_VAL_RE = re.compile(r"^\d+$")

# Wordlist: IDs 1-200 (small & fast; extend via context['ffuf_wordlist'])
_BUILTIN_IDS = "\n".join(str(i) for i in range(1, 201))


def _has_id_param(url: str) -> str | None:
    """Return the first ID-like parameter name, or None."""
    qs = parse_qs(urlparse(url).query)
    for k, vals in qs.items():
        if _ID_PARAM_RE.search(k) and vals and _NUMERIC_VAL_RE.match(vals[0]):
            return k
    return None


def _build_fuzz_url(url: str, param: str) -> str:
    return re.sub(
        rf"({re.escape(param)}=)\d+",
        r"\1FUZZ",
        url,
        count=1,
        flags=re.IGNORECASE,
    )


@register_active
async def ffuf_idor_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fuzz numeric ID parameters to detect IDOR vulnerabilities using ffuf."""
    param = _has_id_param(url)
    if not param:
        raise DetectorSkip("URL has no numeric ID parameters suitable for IDOR fuzzing")

    # Cap total ffuf runs per scan
    counter_key = "_ffuf_idor_count"
    count = context.get(counter_key, 0)
    if count >= 15:
        raise DetectorSkip("ffuf IDOR run limit (15) reached for this scan")
    context[counter_key] = count + 1

    binary = shutil.which("ffuf")
    if not binary:
        raise DetectorSkip("`ffuf` binary not found in PATH")

    fuzz_url = _build_fuzz_url(url, param)
    if "FUZZ" not in fuzz_url:
        raise DetectorSkip("could not build FUZZ URL")

    # Resolve wordlist
    wordlist_path = context.get("ffuf_wordlist") or context.get("id_wordlist")
    if wordlist_path and os.path.exists(str(wordlist_path)):
        wl = str(wordlist_path)
        tmp_wl = None
    else:
        tmp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp_file.write(_BUILTIN_IDS)
        tmp_file.close()
        wl = tmp_file.name
        tmp_wl = tmp_file.name

    try:
        cmd = [
            binary,
            "-u", fuzz_url,
            "-w", wl,
            "-mc", "200,201,204",
            "-fc", "404,401,403",
            "-t", "40",
            "-json",
            "-s",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            raise DetectorSkip("ffuf IDOR timed out after 120s")
    finally:
        if tmp_wl:
            try:
                os.unlink(tmp_wl)
            except Exception:
                pass

    findings: List[Dict[str, Any]] = []
    for line in (stdout or b"").decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        hit_url = item.get("url", "")
        status = item.get("status", 0)
        length = item.get("length", 0)
        words = item.get("words", 0)
        fuzz_val = item.get("input", {}).get("FUZZ", "") if isinstance(item.get("input"), dict) else ""

        findings.append({
            "type": "Potential IDOR",
            "severity": "high",
            "url": hit_url or fuzz_url,
            "detector": "ffuf_idor_detector",
            "title": f"[ffuf] Potential IDOR — {param}={fuzz_val} → HTTP {status}",
            "description": (
                f"ffuf found that {param}={fuzz_val} returns HTTP {status} (length={length}, words={words}). "
                "The server responds to different IDs which may indicate missing authorization checks (IDOR)."
            ),
            "evidence": (
                f"Template URL: {fuzz_url}\n"
                f"Fuzzed URL:   {hit_url}\n"
                f"Param: {param}={fuzz_val}\n"
                f"HTTP Status: {status}\n"
                f"Response length: {length} bytes, {words} words"
            ),
            "payload": f"{param}={fuzz_val}",
            "status_code": status,
            "param": param,
            "confidence": "medium",
            "needs_verification": True,
            "category": "business_logic",
        })

    return findings

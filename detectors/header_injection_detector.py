# detectors/header_injection_detector.py
# Active detector: header injection checks (Host, X-Forwarded-For, X-Real-IP, Referer, User-Agent).
# Non-destructive by default; uses a unique marker per target and checks for reflection / status changes.

import asyncio
import uuid
from detectors.registry import register_active

HEADER_TEMPLATES = {
    "Host": "%s.example.com",
    "X-Forwarded-For": "%s",
    "X-Real-IP": "127.0.0.1",
    "Referer": "https://%s.example.com/",
    "User-Agent": "fuzzer-%s",
    "Forwarded": "for=%s",
}


@register_active
async def detect_header_injection(session, url, context):
    """
    Injects benign header values containing a unique marker and looks for:
      - marker reflected in response body
      - marker reflected in response headers
      - redirect Location containing marker
      - status change vs baseline
    Returns list of findings dicts: {type,evidence,how_found,severity,payload,test_url}
    """
    findings = []
    if not url:
        return findings

    marker = f"hdr-{uuid.uuid4().hex[:8]}"

    # baseline fetch
    try:
        async with session.get(url, allow_redirects=True) as r:
            try:
                baseline_body = await r.text()
            except Exception:
                baseline_body = ""
            baseline_status = r.status
    except Exception:
        baseline_body = ""
        baseline_status = None

    async def _do_request(headers_override):
        try:
            async with session.get(url, headers=headers_override, allow_redirects=True) as resp:
                try:
                    body = await resp.text()
                except Exception:
                    body = ""
                status = resp.status
                resp_headers = dict(resp.headers)
                # get final redirect location if available
                loc = resp_headers.get("Location") or resp_headers.get("location") or ""
                return status, body, resp_headers, loc
        except Exception:
            return None, "", {}, ""

    for hname, template in HEADER_TEMPLATES.items():
        # format payload where placeholder exists
        if "%s" in template:
            value = template % marker
        else:
            value = template

        headers_override = {hname: value}

        status, body, resp_headers, loc = await _do_request(headers_override)
        if status is None:
            # request failed; skip
            continue

        # checks
        reflected_in_body = marker in (body or "")
        reflected_in_headers = any(marker in (v or "") for v in resp_headers.values())
        location_contains = marker in (loc or "")
        status_changed = (baseline_status is not None and baseline_status != status)
        len_diff = abs(len(body or "") - len(baseline_body or ""))

        if reflected_in_body or reflected_in_headers or location_contains or status_changed or len_diff > 200:
            sev = "low"
            if reflected_in_body or reflected_in_headers or location_contains:
                sev = "medium"
            if status_changed and ("500" in str(status) or reflected_in_body):
                sev = "high"

            evidence_parts = []
            if reflected_in_body:
                evidence_parts.append("marker reflected in response body")
            if reflected_in_headers:
                evidence_parts.append("marker reflected in response headers")
            if location_contains:
                evidence_parts.append("marker found in redirect Location")
            if status_changed:
                evidence_parts.append(f"status changed: {baseline_status} -> {status}")
            if len_diff > 200:
                evidence_parts.append(f"body length changed by {len_diff} bytes")

            findings.append({
                "type": "Header Injection / Header Reflection",
                "evidence": "; ".join(evidence_parts),
                "how_found": f"Injected header `{hname}: {value}` and observed response differences",
                "severity": sev,
                "payload": f"{hname}={value}",
                "test_url": url,
            })

        # polite delay
        await asyncio.sleep(0.10)

    return findings

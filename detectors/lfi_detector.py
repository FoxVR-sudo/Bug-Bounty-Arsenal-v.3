# detectors/lfi_detector.py
# Active detector: LFI / path traversal probes (non-destructive by default).
# Uses payloads.PAYLOADS["lfi"] entries when present.

import asyncio
from urllib.parse import urlparse, parse_qsl, urlencode
from detectors.registry import register_active
import payloads

LFI_KEYWORDS = ["root:", "root:x", "passwd", "shadow", "nologin", "boot.ini", "win.ini", "HTTP_HOST", "proc/self/environ"]


@register_active
async def detect_lfi(session, url, context):
    """
    Active LFI / path traversal detector.
    Non-destructive by default; will skip destructive payloads if any are flagged.
    Returns list of findings dicts: {type,evidence,how_found,severity,payload,test_url}
    """
    findings = []
    if not url:
        return findings

    try:
        parsed = urlparse(url)
        # baseline
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

        # Pre-filter: drop keywords that already appear in the baseline response.
        # A keyword present before injection means it's not evidence of LFI —
        # it could be a CMS page, documentation, or framework error that legitimately
        # contains words like "root:" or "passwd".
        active_lfi_keywords = [
            k for k in LFI_KEYWORDS
            if k.lower() not in (baseline_body or "").lower()
        ]

        # gather lfi payloads from centralized payloads
        lfi_entries = []
        for ptype, entries in getattr(payloads, "PAYLOADS", {}).items():
            if ptype == "lfi":
                for ent in entries:
                    destructive = bool(ent.get("destructive", False))
                    template = ent.get("payload") if isinstance(ent, dict) else str(ent)
                    lfi_entries.append((template, destructive, ent.get("description", "")))

        # fallback if none defined
        if not lfi_entries:
            lfi_entries = [
                ("../../etc/passwd", False, "fallback passwd probe"),
                ("../../../../windows/win.ini", False, "fallback win.ini probe"),
            ]

        # helpers
        async def _do_get(u):
            try:
                async with session.get(u, allow_redirects=True) as resp:
                    try:
                        b = await resp.text()
                    except Exception:
                        b = ""
                    return resp.status, b
            except Exception:
                return None, ""

        # Test query parameters (replace each value)
        orig_qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if orig_qs:
            for param in list(orig_qs.keys()):
                for payload_val, destructive, desc in lfi_entries:
                    if destructive and not bool(context.get("allow_destructive", False)):
                        continue
                    new_qs = orig_qs.copy()
                    new_qs[param] = payload_val
                    new_query = urlencode(list(new_qs.items()))
                    test_url = parsed._replace(query=new_query).geturl()

                    status, body = await _do_get(test_url)
                    if status is None:
                        continue

                    keyword_hit = any(k.lower() in (body or "").lower() for k in active_lfi_keywords)
                    len_diff = abs(len(body or "") - len(baseline_body or ""))
                    status_changed = (baseline_status is not None and baseline_status != status)

                    if keyword_hit or len_diff > 200 or status_changed:
                        # Downgrade heuristic-only (length/status) to low; elevate keyword hits.
                        if keyword_hit:
                            sev = "high"
                            evidence_text = "LFI keywords matched in response (not present in baseline)"
                        else:
                            sev = "low"  # previously medium; reduce noise
                            evidence_text = f"Body length change: {len_diff} bytes (no keyword markers)"
                        findings.append({
                            "type": "Local File Inclusion (possible)",
                            "evidence": evidence_text,
                            "how_found": f"Injected LFI payload into query parameter '{param}'",
                            "severity": sev,
                            "payload": f"{param}={payload_val}",
                            "test_url": test_url,
                        })
                        # small delay to be polite
                        await asyncio.sleep(0.12)

        # Test path-based traversal: replace last path segment and also append payload
        path = parsed.path or "/"
        segs = [s for s in path.split("/") if s]
        candidates = []
        if segs:
            # replace last segment
            for payload_val, destructive, desc in lfi_entries:
                if destructive and not bool(context.get("allow_destructive", False)):
                    continue
                new_segs = segs[:-1] + [payload_val]
                new_path = "/" + "/".join(new_segs)
                candidates.append((payload_val, parsed._replace(path=new_path).geturl()))
                # append payload
                new_path2 = "/" + "/".join(segs + [payload_val])
                candidates.append((payload_val, parsed._replace(path=new_path2).geturl()))
        else:
            # root path: append payload
            for payload_val, destructive, desc in lfi_entries:
                if destructive and not bool(context.get("allow_destructive", False)):
                    continue
                new_path = "/" + payload_val
                candidates.append((payload_val, parsed._replace(path=new_path).geturl()))

        for payload_val, test_url in candidates:
            status, body = await _do_get(test_url)
            if status is None:
                continue

            keyword_hit = any(k.lower() in (body or "").lower() for k in active_lfi_keywords)
            len_diff = abs(len(body or "") - len(baseline_body or ""))
            status_changed = (baseline_status is not None and baseline_status != status)

            if keyword_hit or len_diff > 200 or status_changed:
                if keyword_hit:
                    sev = "high"
                    evidence_text = "LFI keywords matched in response (not present in baseline)"
                else:
                    sev = "low"
                    evidence_text = f"Body length change: {len_diff} bytes (no keyword markers)"
                findings.append({
                    "type": "Local File Inclusion (possible)",
                    "evidence": evidence_text,
                    "how_found": f"Injected LFI payload into path (payload: {payload_val})",
                    "severity": sev,
                    "payload": payload_val,
                    "test_url": test_url,
                })
                await asyncio.sleep(0.12)

    except Exception as e:
        findings.append({
            "type": "LFI Detector Error",
            "evidence": str(e),
            "how_found": "internal error",
            "severity": "low",
            "payload": None,
            "test_url": url,
        })

    return findings

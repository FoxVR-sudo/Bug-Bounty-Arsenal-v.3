# detectors/injector.py
# Active injector: generates safe injections using payloads and performs confirmation checks.
import uuid
from urllib.parse import urlparse, parse_qs, urlencode
import logging

from detectors.registry import register_active, await_host_token
import payloads

logger = logging.getLogger(__name__)


@register_active
async def injector(session, url, context):
    """
    Active injector detector.
    - Uses candidate params (query params + discovered form names) to inject safe payloads.
    - Performs a confirmation check with a different marker before returning a finding.
    Context keys:
      - allow_destructive: bool
      - per_host_rate: float (optional)
    Returns: list[dict] findings.
    """
    findings = []
    if not url:
        return findings

    allow_destructive = bool(context.get("allow_destructive", False))
    per_host_rate = context.get("per_host_rate", None)

    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        existing_qs = parse_qs(parsed.query, keep_blank_values=True)

        # Build candidate params from query keys + discovered form inputs.
        candidate_params = list(existing_qs.keys() or [])

        forms = context.get("forms", []) or []
        # forms may be list of dicts (new crawler) or list of strings (legacy)
        for form in forms:
            if isinstance(form, dict):
                inputs = form.get("inputs", []) or []
                for name in inputs:
                    if isinstance(name, str):
                        candidate_params.append(name)
            elif isinstance(form, str):
                candidate_params.append(form)

        # dedupe preserving order
        seen = set()
        deduped_params = []
        for p in candidate_params:
            if not isinstance(p, str):
                continue
            if p in seen:
                continue
            seen.add(p)
            deduped_params.append(p)
        candidate_params = deduped_params

        if not candidate_params:
            candidate_params = ["input"]

        waf_mode = bool(context.get("cloudflare_challenge_detected") or context.get("recent_403"))
        scan_mode = str(context.get("scan_mode", "normal")).lower()

        for param in candidate_params:
            for ptype, plist in payloads.PAYLOADS.items():
                if waf_mode and ptype == "sql":
                    prioritized = [c for c in plist if "cloudflare" in (c.get("tags") or [])]
                    fallback = [c for c in plist if c not in prioritized]
                    candidates = prioritized + fallback
                else:
                    candidates = plist

                # Mode-based payload down-selection
                if scan_mode == "safe":
                    # Keep only first few benign payloads (non-destructive) per type
                    reduced = []
                    for entry in candidates:
                        if entry.get("destructive"):
                            continue
                        reduced.append(entry)
                        if len(reduced) >= 5:
                            break
                    candidates = reduced
                elif scan_mode == "brute":
                    # Use all non-destructive payloads unless allow_destructive enabled
                    if not allow_destructive:
                        candidates = [e for e in candidates if not e.get("destructive")]

                for p in candidates:
                    if p.get("destructive", False) and not allow_destructive:
                        continue

                    marker_a = f"rb-{uuid.uuid4().hex[:8]}"
                    marker_b = f"rb-{uuid.uuid4().hex[:8]}"

                    template = p.get("payload", "%s")
                    # Use .replace() instead of % formatting to avoid issues with %C, %2e, etc in payloads
                    payload_a = template.replace("%s", marker_a) if "%s" in template else template
                    payload_b = template.replace("%s", marker_b) if "%s" in template else template

                    # build test URL A
                    new_qs = dict(existing_qs)
                    new_qs[param] = [payload_a]
                    new_query = urlencode(new_qs, doseq=True)
                    test_url_a = parsed._replace(query=new_query).geturl()

                    # throttle using shared token-bucket
                    await await_host_token(host, per_host_rate)

                    try:
                        async with session.get(test_url_a, allow_redirects=True) as resp_a:
                            try:
                                body_a = await resp_a.text()
                            except Exception:
                                body_a = ""
                            dict(resp_a.headers)
                            resp_a.status
                    except Exception as e:
                        logger.debug("Injector request failed for %s: %s", test_url_a, e)
                        continue

                    if marker_a in (body_a or ""):
                        # confirmation request B
                        new_qs[param] = [payload_b]
                        new_query_b = urlencode(new_qs, doseq=True)
                        test_url_b = parsed._replace(query=new_query_b).geturl()

                        await await_host_token(host, per_host_rate)

                        try:
                            async with session.get(test_url_b, allow_redirects=True) as resp_b:
                                try:
                                    body_b = await resp_b.text()
                                except Exception:
                                    body_b = ""
                                headers_b = dict(resp_b.headers)
                                status_b = resp_b.status
                        except Exception as e:
                            logger.debug("Injector confirmation request failed for %s: %s", test_url_b, e)
                            continue

                        # CRITICAL FIX: Verify that marker_b is reflected and marker_a is NOT
                        # This prevents false positives from static content
                        # ALSO: Check it's not just URL reflection (Cloudflare/CDN error pages)
                        if marker_b in (body_b or "") and marker_a not in (body_b or ""):
                            # Additional check: marker should not appear in the URL itself in the body
                            # Common false positive: Cloudflare/CDN showing requested URL in error page
                            url_in_body = test_url_b in (body_b or "")
                            cloudflare_page = any(x in (body_b or "").lower() for x in ["cloudflare", "just a moment", "checking your browser"])

                            # Skip if marker only appears because the full URL is shown
                            if url_in_body or cloudflare_page:
                                logger.debug(f"Skipping false positive: URL reflection or CDN page for {test_url_b}")
                                continue

                            # Determine severity based on type and verification method
                            # SSRF reflection-only is LOW severity (needs OOB verification)
                            if ptype == "ssrf":
                                severity = "low"  # Reflection only, use ssrf_oob_detector for real verification
                            elif ptype == "xss":
                                severity = "medium"
                            elif ptype == "sql":
                                severity = "high"
                            else:
                                severity = "medium"

                            findings.append({
                                "type": f"{ptype.upper()} Injection Candidate",
                                "evidence": f"Markers {marker_a} and {marker_b} observed for param '{param}'",
                                "how_found": f"Injected into parameter '{param}' and observed reflection (confirmed)",
                                "severity": severity,
                                "payload": template.replace("%s", marker_a) if "%s" in template else template,
                                "evidence_url": test_url_b,
                                "evidence_body": body_b,
                                "evidence_headers": headers_b,
                                "evidence_status": status_b,
                                "test_param": param,
                                "test_payload_template": template,
                            })
    except Exception as e:
        logger.exception("Injector error for %s: %s", url, e)
    return findings

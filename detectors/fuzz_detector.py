# detectors/fuzz_detector.py
# detectors/fuzz_detector.py
# Active detector: parameter fuzzing and differential response analysis.
# Uses centralized payloads from payloads.py and performs GET param fuzzing + POST/form fuzzing
# Non-destructive by default; destructive payloads require context["allow_destructive"] == True.

import asyncio
import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from detectors.registry import register_active
import payloads
import crawler

ERROR_KEYWORDS = [
    "sql syntax", "mysql", "syntax error", "warning:", "stack trace",
    "exception", "fatal error", "sqlstate", "ORA-", "pg_query", "sqlite error"
]


def _format_payload(template: str, marker: str) -> str:
    try:
        # use %s placeholder if present, otherwise return template as-is
        if "%s" in template:
            return template % marker
        return template
    except Exception:
        return template.replace("%s", marker)


@register_active
async def detect_fuzz(session, url, context):
    """
    Active parameter & form fuzzing / differential response checks.
    Uses payloads.PAYLOADS. Non-destructive by default; will include destructive payloads
    only when context['allow_destructive'] is True.

    Returns list of findings dicts: {type,evidence,how_found,severity,payload,test_url}
    """
    findings = []
    if not url:
        return findings

    marker = f"fuzz-{uuid.uuid4().hex[:8]}"

    # ensure we have discovered forms/params (prefer context from scanner, otherwise call crawler)
    forms_meta = context.get("forms") if isinstance(context, dict) else None
    if forms_meta is None:
        try:
            res = await crawler.discover_params(session, url)
            forms_meta = res.get("forms", [])
        except Exception:
            forms_meta = []

    # normalize forms: if list of strings (legacy), build a single form dict pointing to url
    normalized_forms = []
    if forms_meta:
        for f in forms_meta:
            if isinstance(f, dict):
                # expected structure from crawler: {"action":..., "method":..., "inputs":[...]}
                action = f.get("action") or url
                method = (f.get("method") or "get").strip().lower()
                inputs = [n for n in (f.get("inputs") or []) if isinstance(n, str)]
                normalized_forms.append({"action": action, "method": method, "inputs": inputs})
            elif isinstance(f, str):
                normalized_forms.append({"action": url, "method": "post", "inputs": [f]})
    else:
        normalized_forms = []

    # build baseline GET
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

    # prepare payload candidates from payloads.PAYLOADS
    allow_destructive = bool(context.get("allow_destructive")) if isinstance(context, dict) else False
    candidate_payloads = []
    try:
        for ptype, entries in getattr(payloads, "PAYLOADS", {}).items():
            for ent in entries:
                destructive = bool(ent.get("destructive", False))
                if destructive and not allow_destructive:
                    continue
                template = ent.get("payload") if isinstance(ent, dict) else str(ent)
                desc = ent.get("description") if isinstance(ent, dict) else ""
                candidate_payloads.append((ptype, template, destructive, desc))
    except Exception:
        # fallback simple marker
        candidate_payloads.append(("other", "%s", False, "fallback marker"))

    # parse URL query params
    parsed = urlparse(url)
    orig_qs_list = parse_qsl(parsed.query, keep_blank_values=True)
    orig_qs = dict(orig_qs_list)

    async def _request_get(test_url):
        try:
            async with session.get(test_url, allow_redirects=True) as resp:
                try:
                    b = await resp.text()
                except Exception:
                    b = ""
                return resp.status, b
        except Exception:
            return None, ""

    async def _request_post(target, data):
        try:
            async with session.post(target, data=data, allow_redirects=True) as resp:
                try:
                    b = await resp.text()
                except Exception:
                    b = ""
                return resp.status, b
        except Exception:
            return None, ""

    # --- GET param fuzzing ---
    if orig_qs:
        for param in list(orig_qs.keys()):
            for ptype, template, destructive, desc in candidate_payloads:
                payload_val = _format_payload(template, marker)
                test_qs = orig_qs.copy()
                test_qs[param] = payload_val
                new_q = urlencode(list(test_qs.items()))
                test_parsed = parsed._replace(query=new_q)
                test_url = urlunparse(test_parsed)

                status, body = await _request_get(test_url)
                if status is None:
                    continue

                len_diff = abs(len(body or "") - len(baseline_body or ""))
                status_changed = (baseline_status is not None and baseline_status != status)
                keyword_hit = any(k.lower() in (body or "").lower() for k in ERROR_KEYWORDS)
                reflected = payload_val in (body or "")

                if status_changed or len_diff > 50 or keyword_hit or reflected:
                    likely = "Probe"
                    sev = "low"
                    if ptype.lower().startswith("sql") or keyword_hit:
                        likely = "SQL Injection Indicator"
                        sev = "high" if keyword_hit or status == 500 else "medium"
                    elif ptype.lower().startswith("xss"):
                        likely = "Reflected XSS (possible)"
                        sev = "medium" if reflected else "low"
                    elif ptype.lower().startswith("lfi"):
                        likely = "Local File Inclusion (possible)"
                        sev = "high" if ("root:" in (body or "") or "passwd" in (body or "")) else "medium"
                    else:
                        likely = f"{ptype} Probe"

                    findings.append({
                        "type": likely,
                        "evidence": f"Status {baseline_status} -> {status}" if status_changed else
                                    (f"Body length change: {len_diff} bytes" if len_diff > 50 else
                                     ("Payload reflected in response" if reflected else "Error keyword matched in response")),
                                    "how_found": f"Injected {ptype} payload into query parameter '{param}'",
                                    "severity": sev,
                                    "payload": f"{param}={payload_val}",
                                    "test_url": test_url,
                    })

                    # small delay to avoid hammering
                    await asyncio.sleep(0.12)

    # --- POST / form fuzzing ---
    # Use normalized_forms which contains dicts with action/method/inputs
    for form in normalized_forms:
        action = form.get("action") or url
        method = (form.get("method") or "get").strip().lower()
        inputs = form.get("inputs") or []
        if not inputs:
            continue

        for field in inputs:
            for ptype, template, destructive, desc in candidate_payloads:
                payload_val = _format_payload(template, marker)
                # blank other fields
                form_data = {name: "" for name in inputs}
                form_data[field] = payload_val

                if method == "post":
                    status, body = await _request_post(action, form_data)
                else:
                    # for GET forms, build query params
                    parsed_action = urlparse(action)
                    base_q = dict(parse_qsl(parsed_action.query, keep_blank_values=True))
                    base_q.update(form_data)
                    new_q = urlencode(list(base_q.items()))
                    test_url = parsed_action._replace(query=new_q).geturl()
                    status, body = await _request_get(test_url)

                if status is None:
                    continue

                len_diff = abs(len(body or "") - len(baseline_body or ""))
                status_changed = (baseline_status is not None and baseline_status != status)
                keyword_hit = any(k.lower() in (body or "").lower() for k in ERROR_KEYWORDS)
                reflected = payload_val in (body or "")

                if status_changed or len_diff > 50 or keyword_hit or reflected:
                    likely = "Probe"
                    sev = "low"
                    if ptype.lower().startswith("sql") or keyword_hit:
                        likely = "SQL Injection Indicator"
                        sev = "high" if keyword_hit or status == 500 else "medium"
                    elif ptype.lower().startswith("xss"):
                        likely = "Reflected XSS (possible)"
                        sev = "medium" if reflected else "low"
                    else:
                        likely = f"{ptype} Probe"

                    findings.append({
                        "type": likely,
                        "evidence": (f"POST to {action} with field '{field}'; status {baseline_status} -> {status}"
                                     if method == "post" and status_changed else
                                     (f"Body length change: {len_diff} bytes" if len_diff > 50 else
                                      ("Payload reflected in response" if reflected else "Error keyword matched in response"))),
                        "how_found": f"Injected {ptype} payload into form field '{field}' via {method.upper()}",
                        "severity": sev,
                        "payload": f"{field}={payload_val}",
                        "test_url": action if method == "post" else test_url,
                    })

                    await asyncio.sleep(0.12)

    return findings

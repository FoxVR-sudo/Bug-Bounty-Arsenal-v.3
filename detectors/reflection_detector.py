# detectors/reflection_detector.py
# Active detector: използва подадения session + безопасен маркер.
import uuid
from urllib.parse import urlparse
from detectors.registry import register_active


@register_active
async def detect_reflections(session, url, context):
    """
    Active, non-destructive reflection test.
    Returns list of findings dicts: {type,evidence,how_found,severity,payload}
    """
    findings = []
    if not url:
        return findings

    try:
        # 16-char marker reduces collision probability to 1/2^64 vs 1/2^32 for 8-char
        marker = f"rb-{uuid.uuid4().hex[:16]}"
        parsed = urlparse(url)
        sep = '&' if parsed.query else '?'
        test_url = f"{url}{sep}_ref_test={marker}"

        async with session.get(test_url, allow_redirects=True) as resp:
            try:
                text = await resp.text()
            except Exception:
                text = ""

            if marker in text:
                findings.append({
                    "type": "Reflected Input",
                    "evidence": f"Marker `{marker}` found in response body.",
                    "how_found": "Injected benign marker in query parameter and observed it reflected in response",
                    "severity": "low",
                    "payload": f"_ref_test={marker}",
                    "test_url": test_url
                })
    except Exception as e:
        findings.append({
            "type": "Reflection Detector Error",
            "evidence": str(e),
            "how_found": "error",
            "severity": "low",
            "payload": None,
            "test_url": url
        })

    return findings

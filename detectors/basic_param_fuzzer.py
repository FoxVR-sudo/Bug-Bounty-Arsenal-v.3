from urllib.parse import urlparse, urlunparse, urlencode

from detectors.registry import register_active

COMMON_PARAMS = [
    ("file", "../../etc/passwd"),
    ("name", "../../etc/passwd"),
    ("input", "<script>alert(1)</script>"),
    ("key", "debug"),
    ("url", "http://example.com"),
    ("q", "../../../../etc/passwd"),
    ("search", "../../../../etc/passwd"),
]


class BasicParamFuzzer:
    def __init__(self, session, base_url, logger=None):
        self.session = session
        self.base_url = base_url
        self.logger = logger

    async def fuzz(self):
        results = []
        for param, payload in COMMON_PARAMS:
            url = self._build_url(param, payload)
            if self.logger:
                self.logger.debug(f"[BasicParamFuzzer] Testing {url}")
            try:
                async with self.session.get(url, timeout=10) as resp:
                    text = await resp.text()
                    result = self._analyze_response(url, param, payload, text)
                    if result:
                        results.append(result)
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"[BasicParamFuzzer] Error: {e}")
        return results

    def _build_url(self, param, payload):
        parsed = urlparse(self.base_url)
        query = urlencode({param: payload})
        return urlunparse(parsed._replace(query=query))

    def _analyze_response(self, url, param, payload, text):
        # Simple checks for classic LFI, XSS, debug, open redirect
        if "root:x:" in text or "[extensions]" in text:
            return {"type": "LFI", "url": url, "evidence": "Found /etc/passwd marker"}
        if payload in text:
            return {"type": "Reflection/XSS", "url": url, "evidence": f"Payload reflected: {payload}"}
        if "debug" in text.lower() and param == "key":
            return {"type": "Debug Key", "url": url, "evidence": "Debug info in response"}
        if payload.startswith("http") and payload in text:
            return {"type": "Open Redirect", "url": url, "evidence": f"Redirected to: {payload}"}
        return None


@register_active
async def basic_param_fuzzer(session, url: str, context: dict):
    fuzzer = BasicParamFuzzer(session, url)
    fuzzer_findings = await fuzzer.fuzz()

    findings = []
    for f in fuzzer_findings:
        ftype = f.get("type") or "Finding"
        severity = "low"
        if ftype == "LFI":
            severity = "medium"
        elif "Redirect" in ftype:
            severity = "low"
        elif "XSS" in ftype:
            severity = "low"

        findings.append(
            {
                "url": f.get("url", url),
                "type": f"Basic Param Fuzzer: {ftype}",
                "severity": severity,
                "evidence": f.get("evidence", ""),
                "how_found": "basic_param_fuzzer",
                "detector": "basic_param_fuzzer",
            }
        )
    return findings

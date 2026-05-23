"""
JavaScript File Analyzer for 0-Day Hunting
Mines JavaScript files for hidden API endpoints, debug flags, and sensitive data
"""
import json
import re
import requests
from urllib.parse import urljoin
from typing import Dict, List, Any
from detectors.registry import register_active


class JSFileAnalyzer:
    """
    Analyzes JavaScript files to discover:
    - Hidden API endpoints
    - Debug flags and internal URLs
    - Hardcoded credentials
    - Feature flags
    - Internal logic and parameters
    """

    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.findings = []
        self.js_files = []
        self._seen_findings = set()

    @staticmethod
    def _token_kind(value: str) -> str | None:
        v = value.strip()
        patterns = {
            "aws_access_key_id": r"AKIA[0-9A-Z]{16}",
            "github_pat": r"gh[pousr]_[A-Za-z0-9_]{30,}",
            "slack_token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
            "stripe_secret_key": r"sk_(live|test)_[A-Za-z0-9]{20,}",
            "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        }
        for kind, pat in patterns.items():
            if re.fullmatch(pat, v):
                return kind
        return None

    @staticmethod
    def _is_plausible_secret(value: str) -> bool:
        v = value.strip()
        if len(v) < 8:
            return False

        # Drop obvious placeholders/common literals.
        if v.lower() in {"password", "passwd", "your-api-key", "xxx", "token", "secret", "changeme"}:
            return False

        # Minified-library false positives often contain punctuation like ")" or "?".
        # Allow only common token alphabets.
        if not re.fullmatch(r"[A-Za-z0-9_\-\.=+/]{8,}", v):
            return False

        return True

    def _add_finding(self, finding: Dict[str, Any]) -> None:
        key = (
            finding.get("type"),
            finding.get("source"),
            finding.get("endpoint") or finding.get("url") or finding.get("credential") or finding.get("flag"),
        )
        if key in self._seen_findings:
            return
        self._seen_findings.add(key)
        self.findings.append(finding)

    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            # Step 1: Discover JS files
            self.discover_js_files()

            # Step 2: Analyze each JS file
            for js_url in self.js_files[:10]:  # Limit to 10 files
                self.analyze_js_file(js_url)

            return {
                'vulnerable': len(self.findings) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'js_files_analyzed': len(self.js_files),
                'details': {
                    'api_endpoints': [f for f in self.findings if f['type'] == 'api_endpoint'],
                    'debug_flags': [f for f in self.findings if f['type'] == 'debug_flag'],
                    'credentials': [f for f in self.findings if f['type'] == 'credentials'],
                    'internal_urls': [f for f in self.findings if f['type'] == 'internal_url'],
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }

    def discover_js_files(self):
        """Discover JavaScript files from the target"""
        try:
            # Get main page
            response = requests.get(self.target, timeout=10, verify=False)

            # Find JS files in HTML
            js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
            matches = re.findall(js_pattern, response.text)

            for match in matches:
                js_url = urljoin(self.target, match)
                if js_url not in self.js_files:
                    self.js_files.append(js_url)

            # Common JS file paths
            common_paths = [
                '/js/main.js',
                '/js/app.js',
                '/static/js/bundle.js',
                '/assets/js/app.js',
                '/build/main.js',
            ]

            for path in common_paths:
                js_url = urljoin(self.target, path)
                if js_url not in self.js_files:
                    self.js_files.append(js_url)

        except Exception:
            pass

    def analyze_js_file(self, js_url: str):
        """Analyze individual JavaScript file"""
        try:
            response = requests.get(js_url, timeout=10, verify=False)
            content = response.text

            # Pattern 1: API endpoints
            self.find_api_endpoints(content, js_url)

            # Pattern 2: Debug flags
            self.find_debug_flags(content, js_url)

            # Pattern 3: Credentials
            self.find_credentials(content, js_url)

            # Pattern 4: Internal URLs
            self.find_internal_urls(content, js_url)

            # Pattern 5: Feature flags
            self.find_feature_flags(content, js_url)

        except Exception:
            pass

    def find_api_endpoints(self, content: str, source: str):
        """Find API endpoints in JavaScript"""
        patterns = [
            r'["\']/(api|v1|v2|graphql|internal)/[a-zA-Z0-9/_-]+["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+/api/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match if isinstance(match, str) else match[-1]
                if '/api' in endpoint or '/internal' in endpoint:
                    self._add_finding({
                        'type': 'api_endpoint',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'source': source,
                        'description': f'Hidden API endpoint found: {endpoint}'
                    })

    def find_debug_flags(self, content: str, source: str):
        """Find debug flags and development features"""
        patterns = [
            r'debug\s*[:=]\s*(true|false|1|0)',
            r'isDebug\s*[:=]\s*(true|false)',
            r'DEBUG_MODE\s*[:=]\s*(true|false)',
            r'development\s*[:=]\s*(true|false)',
            r'enableDebug\s*[:=]\s*function',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self._add_finding({
                    'type': 'debug_flag',
                    'severity': 'low',
                    'flag': match,
                    'source': source,
                    'description': f'Debug flag found: {match} (may enable hidden features)'
                })

    def find_credentials(self, content: str, source: str):
        """Find hardcoded credentials"""
        patterns = [
            r'password\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'apiKey\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'secret\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'token\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'api_key\s*[:=]\s*["\']([^"\']{10,})["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Skip common placeholders
                if match.lower() in ['password', 'your-api-key', 'xxx', 'token', 'secret']:
                    continue

                value = str(match).strip()
                if not self._is_plausible_secret(value):
                    continue

                kind = self._token_kind(value)
                if kind:
                    sev = "high"
                    confidence = "high"
                else:
                    # Heuristic-only: keep conservative.
                    sev = "medium" if len(value) >= 20 else "low"
                    confidence = "medium" if len(value) >= 20 else "low"

                self._add_finding({
                    'type': 'credentials',
                    'severity': sev,
                    'credential': match[:20] + '...' if len(match) > 20 else match,
                    'source': source,
                    'description': 'Potential hardcoded credential found in JavaScript',
                    'confidence': confidence,
                    'needs_verification': confidence != "high",
                    'credential_kind': kind,
                })

    def find_internal_urls(self, content: str, source: str):
        """Find internal/staging URLs"""
        patterns = [
            r'https?://[a-z0-9-]+\.(dev|staging|test|internal|local)[a-z0-9.-]+',
            r'https?://(dev|staging|test|internal)-[a-z0-9.-]+',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self._add_finding({
                    'type': 'internal_url',
                    'severity': 'medium',
                    'url': match,
                    'source': source,
                    'description': f'Internal/staging URL found: {match}'
                })

    def find_feature_flags(self, content: str, source: str):
        """Find feature flags that can be manipulated"""
        patterns = [
            r'isAdmin\s*[:=]\s*(true|false)',
            r'isPremium\s*[:=]\s*(true|false)',
            r'hasAccess\s*[:=]\s*(true|false)',
            r'featureFlag\s*[:=]\s*["\']([^"\']+)["\']',
            r'betaAccess\s*[:=]\s*(true|false)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self._add_finding({
                    'type': 'feature_flag',
                    'severity': 'medium',
                    'flag': match,
                    'source': source,
                    'description': f'Feature flag found: {match} (potential privilege escalation)'
                })

    def calculate_severity(self) -> str:
        """Calculate overall severity based on findings"""
        if not self.findings:
            return 'info'

        severities = [f.get('severity', 'info') for f in self.findings]

        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        elif 'low' in severities:
            return 'low'
        return 'info'


def detect(target: str) -> Dict[str, Any]:
    """Main detection function called by the scanner framework"""
    analyzer = JSFileAnalyzer(target)
    return analyzer.run()


class AsyncJSFileAnalyzer:
    def __init__(self, session, target: str, *, verify_tls: bool = True):
        self.session = session
        self.target = target.rstrip("/")
        self.verify_tls = bool(verify_tls)
        self.findings: List[Dict[str, Any]] = []
        self.js_files: List[str] = []
        self._seen_findings = set()

    @staticmethod
    def _token_kind(value: str) -> str | None:
        return JSFileAnalyzer._token_kind(value)

    @staticmethod
    def _is_plausible_secret(value: str) -> bool:
        return JSFileAnalyzer._is_plausible_secret(value)

    def _add_finding(self, finding: Dict[str, Any]) -> None:
        key = (
            finding.get("type"),
            finding.get("source"),
            finding.get("endpoint") or finding.get("url") or finding.get("credential") or finding.get("flag"),
        )
        if key in self._seen_findings:
            return
        self._seen_findings.add(key)
        self.findings.append(finding)

    async def _get_text(self, url: str) -> str | None:
        ssl_opt = None if self.verify_tls else False
        try:
            async with self.session.get(url, ssl=ssl_opt, allow_redirects=True) as resp:
                if resp.status != 200:
                    return None
                # Size guard: skip files larger than 1 MB to avoid downloading
                # huge minified bundles (some JS bundles exceed 50 MB).
                cl = resp.headers.get("content-length")
                if cl and cl.isdigit() and int(cl) > 1_000_000:
                    return None
                content = await resp.text(errors="replace")
                # Also guard against servers that ignore Content-Length
                if len(content) > 1_000_000:
                    return content[:1_000_000]
                return content
        except Exception:
            return None

    async def discover_js_files(self):
        html = await self._get_text(self.target)
        if html:
            js_pattern = r"<script[^>]+src=[\"']([^\"']+\.js[^\"']*)[\"']"
            matches = re.findall(js_pattern, html, flags=re.IGNORECASE)
            for match in matches:
                js_url = urljoin(self.target, match)
                if js_url not in self.js_files:
                    self.js_files.append(js_url)

        common_paths = [
            "/js/main.js",
            "/js/app.js",
            "/static/js/bundle.js",
            "/assets/js/app.js",
            "/build/main.js",
        ]
        for path in common_paths:
            js_url = urljoin(self.target, path)
            if js_url not in self.js_files:
                self.js_files.append(js_url)

    def find_api_endpoints(self, content: str, source: str):
        patterns = [
            r"[\"']/(api|v1|v2|graphql|internal)/[a-zA-Z0-9/_-]+[\"']",
            r"endpoint\s*[:=]\s*[\"']([^\"']+)[\"']",
            r"url\s*[:=]\s*[\"']([^\"']+/api/[^\"']+)[\"']",
            r"fetch\([\"']([^\"']+)[\"']",
            r"axios\.(get|post|put|delete)\([\"']([^\"']+)[\"']",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match if isinstance(match, str) else match[-1]
                if "/api" in endpoint or "/internal" in endpoint:
                    self._add_finding(
                        {
                            "type": "api_endpoint",
                            "severity": "medium",
                            "endpoint": endpoint,
                            "source": source,
                            "description": f"Hidden API endpoint found: {endpoint}",
                        }
                    )

    def find_debug_flags(self, content: str, source: str):
        patterns = [
            r"debug\s*[:=]\s*(true|false|1|0)",
            r"isDebug\s*[:=]\s*(true|false)",
            r"DEBUG_MODE\s*[:=]\s*(true|false)",
            r"development\s*[:=]\s*(true|false)",
            r"enableDebug\s*[:=]\s*function",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self._add_finding(
                    {
                        "type": "debug_flag",
                        "severity": "low",
                        "flag": match,
                        "source": source,
                        "description": f"Debug flag found: {match} (may enable hidden features)",
                    }
                )

    def find_credentials(self, content: str, source: str):
        patterns = [
            r"password\s*[:=]\s*[\"']([^\"']{4,})[\"']",
            r"apiKey\s*[:=]\s*[\"']([^\"']{10,})[\"']",
            r"secret\s*[:=]\s*[\"']([^\"']{10,})[\"']",
            r"token\s*[:=]\s*[\"']([^\"']{20,})[\"']",
            r"api_key\s*[:=]\s*[\"']([^\"']{10,})[\"']",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if str(match).lower() in ["password", "your-api-key", "xxx", "token", "secret"]:
                    continue
                value = str(match)

                if not self._is_plausible_secret(value):
                    continue

                kind = self._token_kind(value)
                if kind:
                    sev = "high"
                    confidence = "high"
                else:
                    sev = "medium" if len(value) >= 20 else "low"
                    confidence = "medium" if len(value) >= 20 else "low"

                self._add_finding(
                    {
                        "type": "credentials",
                        "severity": sev,
                        "credential": value[:20] + "..." if len(value) > 20 else value,
                        "source": source,
                        "description": "Potential hardcoded credential found in JavaScript",
                        "confidence": confidence,
                        "needs_verification": confidence != "high",
                        "credential_kind": kind,
                    }
                )

    def find_internal_urls(self, content: str, source: str):
        # Capture full URL (not just group matches)
        patterns = [
            r"https?://[a-z0-9.-]+\.(?:dev|staging|test|internal|local)[a-z0-9.-]+",
            r"https?://(?:dev|staging|test|internal)-[a-z0-9.-]+",
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                u = m.group(0)
                self._add_finding(
                    {
                        "type": "internal_url",
                        "severity": "medium",
                        "url": u,
                        "source": source,
                        "description": f"Internal/staging URL found: {u}",
                    }
                )

    def find_feature_flags(self, content: str, source: str):
        patterns = [
            r"isAdmin\s*[:=]\s*(true|false)",
            r"isPremium\s*[:=]\s*(true|false)",
            r"hasAccess\s*[:=]\s*(true|false)",
            r"featureFlag\s*[:=]\s*[\"']([^\"']+)[\"']",
            r"betaAccess\s*[:=]\s*(true|false)",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self._add_finding(
                    {
                        "type": "feature_flag",
                        "severity": "medium",
                        "flag": match,
                        "source": source,
                        "description": f"Feature flag found: {match} (potential privilege escalation)",
                    }
                )

    def calculate_severity(self) -> str:
        if not self.findings:
            return "info"
        severities = [f.get("severity", "info") for f in self.findings]
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        if "low" in severities:
            return "low"
        return "info"

    async def run(self, *, files_limit: int = 10) -> Dict[str, Any]:
        await self.discover_js_files()
        for js_url in self.js_files[: max(0, int(files_limit))]:
            content = await self._get_text(js_url)
            if not content:
                continue

            self.find_api_endpoints(content, js_url)
            self.find_debug_flags(content, js_url)
            self.find_credentials(content, js_url)
            self.find_internal_urls(content, js_url)
            self.find_feature_flags(content, js_url)

        return {
            "vulnerable": len(self.findings) > 0,
            "severity": self.calculate_severity(),
            "findings": self.findings,
            "js_files_analyzed": len(self.js_files),
            "details": {
                "api_endpoints": [f for f in self.findings if f.get("type") == "api_endpoint"],
                "debug_flags": [f for f in self.findings if f.get("type") == "debug_flag"],
                "credentials": [f for f in self.findings if f.get("type") == "credentials"],
                "internal_urls": [f for f in self.findings if f.get("type") == "internal_url"],
            },
        }


@register_active
async def js_file_analyzer(session, url: str, context: Dict[str, Any]):
    """Async JS analyzer using shared aiohttp session."""
    verify_tls = context.get("verify_tls", True)
    analyzer = AsyncJSFileAnalyzer(session, url, verify_tls=bool(verify_tls))
    result = await analyzer.run(files_limit=int(context.get("js_file_analyzer_files_limit", 10)))
    findings = []
    for f in (result or {}).get("findings", []) or []:
        f_type = f.get("type") or "js_finding"
        findings.append(
            {
                "url": url,
                "type": f"JS Analyzer: {f_type}",
                "severity": f.get("severity", "low"),
                "description": f.get("description", "JavaScript analysis finding"),
                "evidence": json.dumps({k: v for k, v in f.items() if k not in {"severity", "description"}}, ensure_ascii=False)[:500],
                "how_found": "js_file_analyzer",
                "detector": "js_file_analyzer",
            }
        )
    return findings

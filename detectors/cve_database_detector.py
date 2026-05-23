#!/usr/bin/env python3
"""
CVE Database Detector - Smart CVE matching using local CVE database
Integrates with cvelistV5 database for fast, accurate vulnerability detection
"""

import aiohttp
from aiohttp import ClientTimeout
import json
import re
from typing import List, Dict, Optional
from pathlib import Path
from dataclasses import dataclass
import os
from detectors.registry import register_active, DetectorSkip


@dataclass
class CVEVulnerability:
    """Represents a matched CVE with context"""
    cve_id: str
    cvss_score: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cwe_id: str
    description: str
    affected_product: str
    affected_versions: List[str]
    references: List[str]
    published_date: str


class CVEDatabaseDetector:
    """
    Smart CVE detector using local cvelistV5 database

    Features:
    - Fast local database lookup (no API limits)
    - Version matching with fuzzy logic
    - Product fingerprinting
    - CVSS-based prioritization
    - HackerOne-ready evidence
    """

    def __init__(self, cve_db_path: str = "/home/foxvr/Documents/cvelistV5-main/cves"):
        self.cve_db_path = Path(cve_db_path)
        self.cache = {}  # CVE cache for performance
        self.tech_stack = {}  # Detected technologies

    async def detect(self, url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Main detection method"""
        findings = []

        # Step 1: Fingerprint technology stack
        tech_stack = await self._fingerprint_tech_stack(url, session)

        # Step 2: Find CVEs for detected technologies
        for tech in tech_stack:
            cves = await self._find_cves_for_tech(tech)

            for cve in cves:
                # Step 3: Verify version matches
                if self._version_matches(tech['version'], cve.affected_versions):
                    findings.append({
                        "type": "CVE Vulnerability",
                        "severity": cve.severity,
                        "url": url,
                        "cve_id": cve.cve_id,
                        "cvss": cve.cvss_score,
                        "cwe": cve.cwe_id,
                        "product": cve.affected_product,
                        "detected_version": tech['version'],
                        "affected_versions": ", ".join(cve.affected_versions),
                        "description": cve.description[:200] + "...",
                        "references": cve.references[:3],
                        "evidence": f"Detected {tech['name']} {tech['version']} vulnerable to {cve.cve_id}",
                        "exploitation": "Check CVE references for PoC exploits"
                    })

        return findings

    async def _fingerprint_tech_stack(self, url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Detect technologies and versions from target"""
        tech_stack = []

        try:
            async with session.get(url, timeout=ClientTimeout(total=10)) as response:
                headers = response.headers
                html = await response.text()

                # Server detection
                server = headers.get('Server', '')
                if server:
                    tech_stack.extend(self._parse_server_header(server))

                # X-Powered-By
                powered_by = headers.get('X-Powered-By', '')
                if powered_by:
                    tech_stack.extend(self._parse_powered_by(powered_by))

                # HTML meta tags & comments
                tech_stack.extend(self._parse_html_for_tech(html))

                # JavaScript libraries
                tech_stack.extend(self._detect_js_libraries(html))

                # CMS detection (WordPress, Drupal, Joomla, etc.)
                cms = self._detect_cms(html, headers)
                if cms:
                    tech_stack.append(cms)

        except Exception:
            pass

        return tech_stack

    def _parse_server_header(self, server: str) -> List[Dict]:
        """Parse Server header for tech and version"""
        results = []

        # Common patterns
        patterns = [
            (r'Apache/(\d+\.\d+\.\d+)', 'Apache HTTP Server'),
            (r'nginx/(\d+\.\d+\.\d+)', 'nginx'),
            (r'Microsoft-IIS/(\d+\.\d+)', 'Microsoft IIS'),
            (r'LiteSpeed/(\d+\.\d+\.\d+)', 'LiteSpeed'),
            (r'cloudflare', 'Cloudflare'),  # No version usually
        ]

        for pattern, name in patterns:
            match = re.search(pattern, server, re.IGNORECASE)
            if match:
                version = match.group(1) if '(' in pattern else None
                results.append({
                    'name': name,
                    'version': version,
                    'category': 'server',
                    'confidence': 'high'
                })

        return results

    def _parse_powered_by(self, powered_by: str) -> List[Dict]:
        """Parse X-Powered-By header"""
        results = []

        patterns = [
            (r'PHP/(\d+\.\d+\.\d+)', 'PHP'),
            (r'Express', 'Express.js'),
            (r'ASP\.NET', 'ASP.NET'),
        ]

        for pattern, name in patterns:
            match = re.search(pattern, powered_by, re.IGNORECASE)
            if match:
                version = match.group(1) if '(' in pattern else None
                results.append({
                    'name': name,
                    'version': version,
                    'category': 'framework',
                    'confidence': 'high'
                })

        return results

    def _parse_html_for_tech(self, html: str) -> List[Dict]:
        """Extract tech info from HTML"""
        results = []

        # Meta generator tags
        generator_match = re.search(r'<meta name=["\']generator["\'] content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if generator_match:
            generator = generator_match.group(1)

            # WordPress
            if 'WordPress' in generator:
                version_match = re.search(r'WordPress (\d+\.\d+(?:\.\d+)?)', generator)
                results.append({
                    'name': 'WordPress',
                    'version': version_match.group(1) if version_match else None,
                    'category': 'cms',
                    'confidence': 'high'
                })

        return results

    def _detect_js_libraries(self, html: str) -> List[Dict]:
        """Detect JavaScript library versions"""
        results = []

        # jQuery
        jquery_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', html, re.IGNORECASE)
        if jquery_match:
            results.append({
                'name': 'jQuery',
                'version': jquery_match.group(1),
                'category': 'javascript',
                'confidence': 'high'
            })

        # React
        react_match = re.search(r'react[.-](\d+\.\d+\.\d+)', html, re.IGNORECASE)
        if react_match:
            results.append({
                'name': 'React',
                'version': react_match.group(1),
                'category': 'javascript',
                'confidence': 'medium'
            })

        return results

    def _detect_cms(self, html: str, headers: dict) -> Optional[Dict]:
        """Detect CMS and version"""

        # WordPress
        if 'wp-content' in html or 'wp-includes' in html:
            # Try to get version from readme
            version_match = re.search(r'wordpress.*?(\d+\.\d+(?:\.\d+)?)', html, re.IGNORECASE)
            return {
                'name': 'WordPress',
                'version': version_match.group(1) if version_match else None,
                'category': 'cms',
                'confidence': 'high'
            }

        # Drupal
        if 'Drupal' in html or 'sites/default' in html:
            return {
                'name': 'Drupal',
                'version': None,
                'category': 'cms',
                'confidence': 'medium'
            }

        return None

    async def _find_cves_for_tech(self, tech: Dict) -> List[CVEVulnerability]:
        """Find CVEs for detected technology"""
        if not tech['name'] or not tech['version']:
            return []

        cves = []
        product_keywords = self._get_product_keywords(tech['name'])

        # Search recent CVEs (2020-2024 for speed)
        for year in range(2024, 2019, -1):
            year_path = self.cve_db_path / str(year)
            if not year_path.exists():
                continue

            # Search in CVE files
            for cve_file in year_path.rglob("*.json"):
                try:
                    cve_data = self._load_cve(cve_file)
                    if cve_data and self._cve_matches_product(cve_data, product_keywords):
                        cve = self._parse_cve_data(cve_data)
                        if cve:
                            cves.append(cve)
                except Exception:
                    continue

                # Limit results for performance
                if len(cves) >= 10:
                    break

            if len(cves) >= 10:
                break

        # Sort by CVSS score (highest first)
        cves.sort(key=lambda x: x.cvss_score, reverse=True)
        return cves[:5]  # Top 5 CVEs

    def _load_cve(self, cve_file: Path) -> Optional[Dict]:
        """Load and cache CVE data"""
        cache_key = str(cve_file)

        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            with open(cve_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.cache[cache_key] = data
                return data
        except Exception:
            return None

    def _get_product_keywords(self, tech_name: str) -> List[str]:
        """Get search keywords for technology"""
        keywords = [tech_name.lower()]

        # Add common variations
        mappings = {
            'Apache HTTP Server': ['apache', 'httpd'],
            'nginx': ['nginx'],
            'WordPress': ['wordpress', 'wp'],
            'Drupal': ['drupal'],
            'jQuery': ['jquery'],
            'PHP': ['php'],
        }

        if tech_name in mappings:
            keywords = mappings[tech_name]

        return keywords

    def _cve_matches_product(self, cve_data: Dict, keywords: List[str]) -> bool:
        """Check if CVE matches product keywords"""
        try:
            # Get affected products
            affected = cve_data.get('containers', {}).get('cna', {}).get('affected', [])

            for item in affected:
                vendor = item.get('vendor', '').lower()
                product = item.get('product', '').lower()

                for keyword in keywords:
                    if keyword in vendor or keyword in product:
                        return True

            # Also check description
            descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
            for desc in descriptions:
                text = desc.get('value', '').lower()
                for keyword in keywords:
                    if keyword in text:
                        return True

        except Exception:
            pass

        return False

    def _parse_cve_data(self, cve_data: Dict) -> Optional[CVEVulnerability]:
        """Parse CVE JSON into CVEVulnerability object"""
        try:
            cna = cve_data.get('containers', {}).get('cna', {})
            metadata = cve_data.get('cveMetadata', {})

            # CVE ID
            cve_id = metadata.get('cveId', '')

            # CVSS Score
            metrics = cna.get('metrics', [])
            cvss_score = 0.0
            severity = 'UNKNOWN'

            for metric in metrics:
                if 'cvssV3_1' in metric:
                    cvss = metric['cvssV3_1']
                    cvss_score = cvss.get('baseScore', 0.0)
                    severity = cvss.get('baseSeverity', 'UNKNOWN')
                    break

            # CWE
            cwe_id = ''
            problem_types = cna.get('problemTypes', [])
            for pt in problem_types:
                for desc in pt.get('descriptions', []):
                    cwe = desc.get('cweId', '')
                    if cwe:
                        cwe_id = cwe
                        break
                if cwe_id:
                    break

            # Description
            descriptions = cna.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''

            # Affected
            affected = cna.get('affected', [])
            affected_product = ''
            affected_versions = []

            if affected:
                item = affected[0]
                vendor = item.get('vendor', '')
                product = item.get('product', '')
                affected_product = f"{vendor} {product}".strip()

                for version_info in item.get('versions', []):
                    version = version_info.get('version', '')
                    if version:
                        affected_versions.append(version)

            # References
            references = []
            for ref in cna.get('references', []):
                url = ref.get('url', '')
                if url:
                    references.append(url)

            # Published date
            published_date = metadata.get('datePublished', '')

            return CVEVulnerability(
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=severity,
                cwe_id=cwe_id,
                description=description,
                affected_product=affected_product,
                affected_versions=affected_versions,
                references=references,
                published_date=published_date
            )

        except Exception:
            return None

    def _version_matches(self, detected_version: Optional[str], affected_versions: List[str]) -> bool:
        """Check if detected version matches affected versions"""
        if not detected_version or not affected_versions:
            return True  # Assume vulnerable if version unknown

        for affected in affected_versions:
            # Simple version matching (can be improved)
            if '<' in affected:
                # e.g., "< 1.7.4"
                max_version = affected.replace('<', '').strip()
                if self._version_compare(detected_version, max_version) < 0:
                    return True
            elif detected_version in affected:
                return True

        return False

    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare two version strings"""
        try:
            parts1 = [int(x) for x in v1.split('.')]
            parts2 = [int(x) for x in v2.split('.')]

            # Pad shorter version
            max_len = max(len(parts1), len(parts2))
            parts1.extend([0] * (max_len - len(parts1)))
            parts2.extend([0] * (max_len - len(parts2)))

            for p1, p2 in zip(parts1, parts2):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1

            return 0
        except Exception:
            return 0  # Can't compare, assume equal


# Detector registration
detector_class = CVEDatabaseDetector
detector_info = {
    "name": "CVE Database Detector",
    "description": "Detects known CVEs using local cvelistV5 database",
    "type": "passive",
    "severity": "varies",
    "confidence": "high"
}


# ── Fast detector using SQLite index ─────────────────────────────────────────

class FastCVEDetector:
    """
    CVE detector backed by the SQLite index from utils.cve_index.

    Replaces the O(250k file reads) loop in CVEDatabaseDetector with an
    indexed SQL lookup that returns results in < 10ms.

    Falls back to CVEDatabaseDetector (slow) when the index is not yet built.
    """

    def __init__(self, cve_db_path: str):
        self.cve_db_path = cve_db_path
        self._legacy = CVEDatabaseDetector(cve_db_path=cve_db_path)

    async def detect(self, url: str, session: aiohttp.ClientSession) -> List[Dict]:
        from utils.cve_index import get_cves_for_product, ensure_index, get_index_stats

        # Make sure the index exists (non-blocking if already built)
        import asyncio, functools
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, functools.partial(ensure_index, self.cve_db_path)
        )

        stats = get_index_stats()
        if not stats.get("built"):
            # Index build failed — fall back to legacy (slow)
            return await self._legacy.detect(url, session)

        # Fingerprint the tech stack (reuse the existing method)
        tech_stack = await self._legacy._fingerprint_tech_stack(url, session)
        if not tech_stack:
            return []

        findings: List[Dict] = []

        for tech in tech_stack:
            tech_name    = (tech.get("name") or "").lower()
            tech_version = tech.get("version")
            if not tech_name:
                continue

            # Normalize keyword the same way cve_index does
            product_key = tech_name.replace(" ", "_")[:64]

            cve_rows = get_cves_for_product(
                product_key,
                db_path=self.cve_db_path,
                limit=10,
                min_cvss=4.0,  # skip negligible findings
            )

            for row in cve_rows:
                # Load full CVE data from file for version check + description
                try:
                    import json as _json
                    raw = _json.loads(Path(row["file_path"]).read_bytes())
                    cve_obj = self._legacy._parse_cve_data(raw)
                    if cve_obj is None:
                        continue

                    # Version check
                    if tech_version and cve_obj.affected_versions:
                        if not self._legacy._version_matches(tech_version, cve_obj.affected_versions):
                            continue

                    cvss_score = cve_obj.cvss_score or float(row.get("cvss_score") or 0)
                    sev = cve_obj.severity.lower() if cve_obj.severity else row.get("severity", "low")

                    findings.append({
                        "type":             "CVE Vulnerability",
                        "severity":         sev,
                        "url":              url,
                        "cve_id":           cve_obj.cve_id,
                        "cvss_score":       cvss_score,
                        "cwe":              cve_obj.cwe_id,
                        "product":          cve_obj.affected_product or tech_name,
                        "detected_version": tech_version,
                        "affected_versions": ", ".join(cve_obj.affected_versions[:5]),
                        "description":      cve_obj.description[:300],
                        "references":       cve_obj.references[:3],
                        "evidence": (
                            f"Detected {tech_name} {tech_version or '?'} "
                            f"matching {cve_obj.cve_id} (CVSS {cvss_score})"
                        ),
                        "confidence":       _cve_confidence(cvss_score, bool(tech_version)),
                        "verified":         False,
                        "how_found":        "cve_database_detector (indexed)",
                        "detector":         "cve_database_detector",
                    })
                except Exception:
                    continue

        # Sort by CVSS descending, keep top 10
        findings.sort(key=lambda f: float(f.get("cvss_score") or 0), reverse=True)
        return findings[:10]


def _cve_confidence(cvss_score: float, version_known: bool) -> int:
    """
    Confidence scoring for CVE matches.

    High CVSS + known version → strong signal.
    Unknown version → version may not actually be vulnerable → lower confidence.
    """
    base = 0
    if cvss_score >= 9.0:
        base = 75
    elif cvss_score >= 7.0:
        base = 65
    elif cvss_score >= 4.0:
        base = 50
    else:
        base = 35

    if version_known:
        base += 15  # version was extracted → version check passed

    return min(90, base)


def _resolve_cve_db_path(context: Optional[Dict]) -> Optional[Path]:
    candidates = [
        (context or {}).get("cve_db_path"),
        os.environ.get("CVE_DB_PATH"),
        "/app/cvelistV5",
        "/app/cvelistV5/cves",
        str(Path.home() / "cvelistV5"),
        str(Path.home() / "cvelistV5" / "cves"),
    ]

    for candidate in candidates:
        if not candidate:
            continue
        path = Path(str(candidate)).expanduser()
        if not path.is_dir():
            continue
        if path.name == "cves" and path.parent.is_dir():
            return path.parent
        return path

    return None


@register_active
async def cve_database_detector(session: aiohttp.ClientSession, url: str, context: Dict):
    """
    Fast CVE detector backed by a SQLite index of cvelistV5.

    On first run (or after a `git pull` of the CVE database), builds a SQLite
    index in ~/.bugbounty_arsenal/cve_index.db.  Subsequent runs are instant.

    Also triggers a background auto-update of the CVE database (weekly).

    Configure via:
      - context['cve_db_path']  or  env CVE_DB_PATH
    """
    cve_db_path = _resolve_cve_db_path(context)
    if cve_db_path is None:
        raise DetectorSkip(
            "CVE database path not found; set CVE_DB_PATH or context['cve_db_path'].\n"
            "Clone with: git clone --depth=1 https://github.com/CVEProject/cvelistV5.git ~/cvelistV5"
        )

    # Background auto-update (weekly, non-blocking)
    import asyncio as _asyncio

    async def _bg_update():
        try:
            from utils.auto_update import update_cve_database
            await update_cve_database(str(cve_db_path))
        except Exception:
            pass

    _asyncio.ensure_future(_bg_update())

    detector = FastCVEDetector(cve_db_path=str(cve_db_path))
    return await detector.detect(url, session)


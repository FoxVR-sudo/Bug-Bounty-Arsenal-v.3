"""
GitHub OSINT Scanner - Advanced reconnaissance through GitHub
Finds leaked secrets, API keys, and sensitive information in public repositories
"""
import os
import requests
import time
from typing import Dict, List, Any
from urllib.parse import urlparse
import asyncio
from detectors.registry import register_active, DetectorSkip


class GitHubOSINT:
    """
    GitHub reconnaissance for finding:
    - Leaked API keys and credentials
    - Exposed secrets in code
    - Developer commits with sensitive data
    - Organization information
    - Repository vulnerabilities
    """

    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.domain = self.extract_domain(target)
        self.findings = []

        # GitHub API (unauthenticated has rate limits)
        self.github_api = "https://api.github.com"
        self.github_search = "https://api.github.com/search/code"

        # Sensitive patterns to search for
        self.secret_patterns = {
            'api_key': [
                'api_key',
                'apikey',
                'api-key',
                'key',
            ],
            'password': [
                'password',
                'passwd',
                'pwd',
                'pass',
            ],
            'token': [
                'token',
                'auth_token',
                'access_token',
                'secret_token',
            ],
            'secret': [
                'secret',
                'api_secret',
                'client_secret',
                'app_secret',
            ],
            'credentials': [
                'credentials',
                'creds',
                'credential',
            ],
            'database': [
                'db_password',
                'database_password',
                'mysql_password',
                'postgres_password',
            ],
            'aws': [
                'aws_access_key_id',
                'aws_secret_access_key',
                'AWS_ACCESS_KEY',
                'AWS_SECRET_KEY',
            ],
        }

        # File extensions to check
        self.sensitive_extensions = [
            '.env',
            '.config',
            '.ini',
            '.yml',
            '.yaml',
            '.json',
            '.xml',
            '.properties',
            '.conf',
        ]

    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            # Search for domain in GitHub
            self.search_domain_mentions()

            # Search for common secret files
            self.search_secret_files()

            # Search for hardcoded credentials
            self.search_hardcoded_secrets()

            # Search for exposed configs
            self.search_config_files()

            return {
                'vulnerable': len(self.findings) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'searches_performed': 4,
                'details': {
                    'leaked_secrets': [f for f in self.findings if f['type'] == 'secret'],
                    'exposed_configs': [f for f in self.findings if f['type'] == 'config'],
                    'credentials': [f for f in self.findings if f['type'] == 'credentials'],
                    'api_keys': [f for f in self.findings if f['type'] == 'api_key'],
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }

    def extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove www. and port
        domain = domain.replace('www.', '').split(':')[0]
        return domain

    def search_domain_mentions(self):
        """Search for domain mentions in GitHub repositories"""
        try:
            # Search GitHub code for domain
            query = f'"{self.domain}"'

            response = requests.get(
                self.github_search,
                params={'q': query, 'per_page': 10},
                headers={'Accept': 'application/vnd.github.v3+json'},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('total_count', 0) > 0:
                    for item in data.get('items', [])[:5]:  # Limit to 5 results
                        self.findings.append({
                            'type': 'domain_mention',
                            'severity': 'medium',
                            'repository': item.get('repository', {}).get('full_name'),
                            'file': item.get('name'),
                            'url': item.get('html_url'),
                            'description': f'Domain {self.domain} found in public repository',
                            'risk': 'May expose internal URLs, API endpoints, or configuration details'
                        })

            time.sleep(2)  # Rate limiting

        except Exception:
            pass

    def search_secret_files(self):
        """Search for common secret files (.env, config.json, etc.)"""
        secret_files = [
            '.env',
            'config.json',
            'credentials.json',
            'secrets.json',
            'api_keys.txt',
            '.aws/credentials',
        ]

        for filename in secret_files[:3]:  # Limit searches
            try:
                query = f'"{self.domain}" filename:{filename}'

                response = requests.get(
                    self.github_search,
                    params={'q': query, 'per_page': 5},
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=15
                )

                if response.status_code == 200:
                    data = response.json()

                    if data.get('total_count', 0) > 0:
                        for item in data.get('items', [])[:3]:
                            self.findings.append({
                                'type': 'secret',
                                'severity': 'critical',
                                'repository': item.get('repository', {}).get('full_name'),
                                'file': filename,
                                'url': item.get('html_url'),
                                'description': f'Sensitive file {filename} found containing {self.domain}',
                                'risk': 'May contain API keys, passwords, or other credentials'
                            })

                time.sleep(3)  # Rate limiting

            except:
                pass

    def search_hardcoded_secrets(self):
        """Search for hardcoded secrets in code"""
        # Search for common secret patterns
        secret_searches = [
            f'{self.domain} password',
            f'{self.domain} api_key',
            f'{self.domain} token',
        ]

        for search_term in secret_searches[:2]:  # Limit searches
            try:
                response = requests.get(
                    self.github_search,
                    params={'q': search_term, 'per_page': 5},
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=15
                )

                if response.status_code == 200:
                    data = response.json()

                    if data.get('total_count', 0) > 0:
                        for item in data.get('items', [])[:2]:
                            self.findings.append({
                                'type': 'credentials',
                                'severity': 'high',
                                'repository': item.get('repository', {}).get('full_name'),
                                'file': item.get('name'),
                                'url': item.get('html_url'),
                                'search_term': search_term,
                                'description': f'Hardcoded credentials found for {self.domain}',
                                'risk': 'Credentials may be valid and usable for authentication'
                            })

                time.sleep(3)  # Rate limiting

            except:
                pass

    def search_config_files(self):
        """Search for exposed configuration files"""
        # Common config patterns that might expose sensitive info
        config_patterns = [
            f'"{self.domain}" extension:yml',
            f'"{self.domain}" extension:env',
        ]

        for pattern in config_patterns[:1]:  # Limit to 1 search
            try:
                response = requests.get(
                    self.github_search,
                    params={'q': pattern, 'per_page': 5},
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=15
                )

                if response.status_code == 200:
                    data = response.json()

                    if data.get('total_count', 0) > 0:
                        for item in data.get('items', [])[:2]:
                            self.findings.append({
                                'type': 'config',
                                'severity': 'medium',
                                'repository': item.get('repository', {}).get('full_name'),
                                'file': item.get('name'),
                                'url': item.get('html_url'),
                                'description': f'Configuration file found referencing {self.domain}',
                                'risk': 'May contain database URLs, API endpoints, or service credentials'
                            })

                time.sleep(3)  # Rate limiting

            except:
                pass

    def calculate_severity(self) -> str:
        """Calculate overall severity"""
        if not self.findings:
            return 'info'

        severities = [f.get('severity', 'info') for f in self.findings]

        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        return 'low'


def detect(target: str) -> Dict[str, Any]:
    """Main detection function"""
    scanner = GitHubOSINT(target)
    return scanner.run()


class AsyncGitHubOSINT:
    def __init__(self, session, target: str, *, token: str):
        self.session = session
        self.target = target.rstrip("/")
        self.domain = GitHubOSINT(target).domain
        self.findings: List[Dict[str, Any]] = []
        self.github_api = "https://api.github.com"
        self.github_search = "https://api.github.com/search/code"
        self.token = token

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "BugBounty-Arsenal",
        }

    async def _get_json(self, url: str, params: Dict[str, Any]) -> Dict[str, Any] | None:
        try:
            async with self.session.get(url, params=params, headers=self._headers(), timeout=20) as resp:
                if resp.status != 200:
                    return None
                try:
                    return await resp.json(content_type=None)
                except Exception:
                    return None
        except Exception:
            return None

    def _add_domain_mentions(self, data: Dict[str, Any] | None):
        if not data or data.get("total_count", 0) <= 0:
            return
        for item in (data.get("items") or [])[:5]:
            repo = (item.get("repository") or {}).get("full_name")
            self.findings.append(
                {
                    "type": "domain_mention",
                    "severity": "medium",
                    "repository": repo,
                    "file": item.get("name"),
                    "url": item.get("html_url"),
                    "description": f"Domain {self.domain} found in public repository",
                    "risk": "May expose internal URLs, API endpoints, or configuration details",
                }
            )

    def _add_secret_file_hits(self, filename: str, data: Dict[str, Any] | None):
        if not data or data.get("total_count", 0) <= 0:
            return
        for item in (data.get("items") or [])[:3]:
            repo = (item.get("repository") or {}).get("full_name")
            self.findings.append(
                {
                    "type": "secret",
                    "severity": "critical",
                    "repository": repo,
                    "file": filename,
                    "url": item.get("html_url"),
                    "description": f"Sensitive file {filename} found containing {self.domain}",
                    "risk": "May contain API keys, passwords, or other credentials",
                }
            )

    def _add_credentials_hits(self, search_term: str, data: Dict[str, Any] | None):
        if not data or data.get("total_count", 0) <= 0:
            return
        for item in (data.get("items") or [])[:2]:
            repo = (item.get("repository") or {}).get("full_name")
            self.findings.append(
                {
                    "type": "credentials",
                    "severity": "high",
                    "repository": repo,
                    "file": item.get("name"),
                    "url": item.get("html_url"),
                    "search_term": search_term,
                    "description": f"Hardcoded credentials found for {self.domain}",
                    "risk": "Credentials may be valid and usable for authentication",
                }
            )

    def _add_config_hits(self, data: Dict[str, Any] | None):
        if not data or data.get("total_count", 0) <= 0:
            return
        for item in (data.get("items") or [])[:2]:
            repo = (item.get("repository") or {}).get("full_name")
            self.findings.append(
                {
                    "type": "config",
                    "severity": "medium",
                    "repository": repo,
                    "file": item.get("name"),
                    "url": item.get("html_url"),
                    "description": f"Configuration file found referencing {self.domain}",
                    "risk": "May contain database URLs, API endpoints, or service credentials",
                }
            )

    def _calculate_severity(self) -> str:
        if not self.findings:
            return "info"
        severities = [f.get("severity", "info") for f in self.findings]
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"

    async def run(
        self,
        *,
        per_page: int = 10,
        sleep_s: float = 1.0,
        secret_files_limit: int = 3,
        secret_searches_limit: int = 2,
        config_searches_limit: int = 1,
    ) -> Dict[str, Any]:
        # Domain mentions
        q = f'"{self.domain}"'
        data = await self._get_json(self.github_search, {"q": q, "per_page": int(per_page)})
        self._add_domain_mentions(data)
        if sleep_s:
            await asyncio.sleep(float(sleep_s))

        # Secret files
        secret_files = [
            ".env",
            "config.json",
            "credentials.json",
            "secrets.json",
            "api_keys.txt",
            ".aws/credentials",
        ]
        for filename in secret_files[: max(0, int(secret_files_limit))]:
            q = f'"{self.domain}" filename:{filename}'
            data = await self._get_json(self.github_search, {"q": q, "per_page": 5})
            self._add_secret_file_hits(filename, data)
            if sleep_s:
                await asyncio.sleep(float(sleep_s))

        # Hardcoded credentials
        secret_searches = [f"{self.domain} password", f"{self.domain} api_key", f"{self.domain} token"]
        for term in secret_searches[: max(0, int(secret_searches_limit))]:
            data = await self._get_json(self.github_search, {"q": term, "per_page": 5})
            self._add_credentials_hits(term, data)
            if sleep_s:
                await asyncio.sleep(float(sleep_s))

        # Exposed configs
        config_patterns = [f'"{self.domain}" extension:yml', f'"{self.domain}" extension:env']
        for term in config_patterns[: max(0, int(config_searches_limit))]:
            data = await self._get_json(self.github_search, {"q": term, "per_page": 5})
            self._add_config_hits(data)
            if sleep_s:
                await asyncio.sleep(float(sleep_s))

        return {
            "vulnerable": len(self.findings) > 0,
            "severity": self._calculate_severity(),
            "findings": self.findings,
            "searches_performed": 4,
            "details": {
                "leaked_secrets": [f for f in self.findings if f.get("type") == "secret"],
                "exposed_configs": [f for f in self.findings if f.get("type") == "config"],
                "credentials": [f for f in self.findings if f.get("type") == "credentials"],
                "api_keys": [f for f in self.findings if f.get("type") == "api_key"],
            },
        }


@register_active
async def github_osint(session, url: str, context: Dict[str, Any]):
    """Async wrapper for GitHubOSINT.

    Requires `GITHUB_TOKEN` due to aggressive rate limits on unauthenticated code search.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise DetectorSkip("github_osint requires GITHUB_TOKEN environment variable")

    gh = AsyncGitHubOSINT(session, url, token=token)
    result = await gh.run(
        per_page=int(context.get("github_osint_per_page", 10)),
        sleep_s=float(context.get("github_osint_sleep_s", 1.0)),
        secret_files_limit=int(context.get("github_osint_secret_files_limit", 3)),
        secret_searches_limit=int(context.get("github_osint_secret_searches_limit", 2)),
        config_searches_limit=int(context.get("github_osint_config_searches_limit", 1)),
    )

    findings = []
    for f in (result or {}).get("findings", []) or []:
        f_kind = (f.get("type") or "finding").lower().strip()

        # GitHub code search results are OSINT leads, not confirmed vulnerabilities.
        # We do not fetch/validate file contents here, so keep severity conservative.
        if f_kind in {"domain_mention", "config"}:
            sev = "info"
        elif f_kind in {"secret", "credentials", "api_key"}:
            sev = "low"
        else:
            sev = "low"

        findings.append(
            {
                "url": url,
                "type": f"GitHub OSINT: {f.get('type', 'finding')}",
                "severity": sev,
                "description": f.get("description", "GitHub OSINT finding"),
                "evidence": f.get("url") or f.get("repository") or "GitHub match",
                "how_found": "github_osint",
                "detector": "github_osint",
                "confidence": "low",
                "needs_verification": True,
            }
        )
    return findings

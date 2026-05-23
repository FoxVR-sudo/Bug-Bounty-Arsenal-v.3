"""
Management command to populate scan categories and detector configurations.
Run after migrations: python manage.py populate_scan_categories
"""
import re
from pathlib import Path

from django.core.management.base import BaseCommand
from scans.category_models import ScanCategory, DetectorConfig


class Command(BaseCommand):
    help = 'Populate scan categories and detector configurations for v3.0'

    def _discover_detector_module_names(self) -> list:
        detectors_dir = Path(__file__).resolve().parents[3] / 'detectors'
        if not detectors_dir.exists():
            return []

        excluded = {
            '__init__.py',
            'views.py',
            'detector_categories.py',
            'injector.py',
            'interactsh_client.py',
            'registry.py',
        }

        names: list[str] = []
        for p in sorted(detectors_dir.glob('*.py')):
            if p.name in excluded:
                continue
            names.append(p.stem)
        return names

    def _humanize_detector_name(self, name: str) -> str:
        s = (name or '').replace('_', ' ').strip()
        if not s:
            return 'Detector'

        replacements = {
            'jwt': 'JWT',
            'ssrf': 'SSRF',
            'oob': 'OOB',
            'xss': 'XSS',
            'sqli': 'SQLi',
            'sql': 'SQL',
            'nosql': 'NoSQL',
            'csrf': 'CSRF',
            'cors': 'CORS',
            'xxe': 'XXE',
            'ssti': 'SSTI',
            'lfi': 'LFI',
            'idor': 'IDOR',
            'api': 'API',
            'graphql': 'GraphQL',
            'oauth': 'OAuth',
            'cve': 'CVE',
            'rce': 'RCE',
        }

        tokens = [t for t in re.split(r'\s+', s.lower()) if t]
        out = []
        for t in tokens:
            if t in replacements:
                out.append(replacements[t])
            elif t == 'detector':
                continue
            else:
                out.append(t.capitalize())
        if not out:
            out = ['Detector']
        return ' '.join(out)

    def _infer_severity_and_tags(self, name: str) -> tuple[str, list]:
        key = (name or '').lower()
        tags: set[str] = set()
        severity = 'medium'

        if 'cve' in key or 'command_injection' in key or 'ssti' in key or 'sql' in key:
            severity = 'critical'
        elif 'ssrf' in key or 'xxe' in key or 'lfi' in key or 'rce' in key or 'auth_bypass' in key:
            severity = 'high'
        elif 'cors' in key or 'csrf' in key or 'headers' in key or 'open_redirect' in key:
            severity = 'medium'
        elif 'recon' in key or 'osint' in key or 'hunter' in key:
            severity = 'low'

        if any(x in key for x in ['xss', 'sql', 'nosql', 'command_injection', 'ssti', 'xxe', 'lfi', 'prototype']):
            tags.add('injection')
        if any(x in key for x in ['api', 'graphql', 'jwt', 'oauth']):
            tags.add('api')
        if any(x in key for x in ['auth', 'brute', 'rate_limit', 'jwt', 'oauth']):
            tags.add('auth')
        if any(
            x in key for x in [
                'recon',
                'osint',
                'secret',
                'backup',
                'domain',
                'subdomain',
                'takeover',
                'file_list',
                'dir_listing']):
            tags.add('recon')
        if any(x in key for x in ['fuzz', 'fuzzer']):
            tags.add('fuzzing')
        if any(x in key for x in ['cve', 'nuclei', 'vuln']):
            tags.add('vuln')

        return severity, sorted(tags)

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING('Populating scan categories and detectors...'))

        # Create categories
        categories = self.create_categories()

        # Create detector configurations
        detectors = self.create_detectors()

        # Assign detectors to categories
        self.assign_to_categories(categories, detectors)

        # Update detector counts
        for category in categories.values():
            category.update_detector_count()

        self.stdout.write(self.style.SUCCESS('\n✅ Successfully created:'))
        self.stdout.write(f'   - {len(categories)} scan categories')
        self.stdout.write(f'   - {len(detectors)} detector configurations')

        # Show category summary
        self.stdout.write(self.style.SUCCESS('\n📊 Category Summary:'))
        for cat_name, category in categories.items():
            count = category.detector_count
            self.stdout.write(
                f'   {category.icon} {category.display_name}: {count} detectors '
                f'({category.required_plan})'
            )

    def create_categories(self):
        """Create scan categories"""
        categories_data = [
            {
                'name': 'recon',
                'display_name': 'Reconnaissance Scan',
                'description': (
                    'Subdomain enumeration, DNS records, WHOIS lookup, technology detection, and infrastructure '
                    'mapping.'
                ),
                'required_plan': 'free',
                'icon': '🔍',
                'order': 1,
            },
            {
                'name': 'web',
                'display_name': 'Web Application Scan',
                'description': (
                    'XSS, SQL injection, CSRF, CORS misconfigurations, security headers, open redirects, and '
                    'common web vulnerabilities.'
                ),
                'required_plan': 'free',
                'icon': '🌐',
                'order': 2,
            },
            {
                'name': 'api',
                'display_name': 'API Security Scan',
                'description': (
                    'GraphQL introspection, REST API testing, JWT vulnerabilities, OAuth misconfigurations, and '
                    'API-specific attacks.'
                ),
                'required_plan': 'free',
                'icon': '🔌',
                'order': 3,
            },
            {
                'name': 'vuln',
                'display_name': 'Vulnerability Scan',
                'description': (
                    'CVE database scanning, known vulnerability detection, version checking, and exploit '
                    'availability.'
                ),
                'required_plan': 'free',
                'icon': '⚠️',
                'order': 4,
            },
            {
                'name': 'mobile',
                'display_name': 'Mobile Security Scan',
                'description': (
                    'Android APK analysis, iOS IPA testing, mobile API security, and app-specific vulnerabilities.'
                ),
                'required_plan': 'free',
                'icon': '📱',
                'order': 5,
            },
        ]

        categories = {}
        for data in categories_data:
            category, created = ScanCategory.objects.update_or_create(
                name=data['name'],
                defaults=data
            )
            categories[data['name']] = category
            status = '✨ Created' if created else '♻️  Updated'
            self.stdout.write(f'{status}: {category.display_name}')

        # Legacy compatibility: keep any existing 'custom' category but mark it inactive.
        try:
            custom = ScanCategory.objects.filter(name='custom').first()
            if custom:
                custom.is_active = False
                custom.order = 999
                custom.save(update_fields=['is_active', 'order'])
                self.stdout.write('ℹ️  Legacy category "custom" found; marked inactive')
        except Exception:
            # Best-effort only
            pass

        return categories

    def create_detectors(self):
        """Create detector configurations for all 40+ detectors"""
        detectors_data = [
            # XSS & Injection Detectors
            {
                'name': 'xss_pattern_detector',
                'display_name': 'XSS Pattern Detection',
                'description': (
                    'Cross-Site Scripting (XSS) vulnerability detection using pattern matching and payload '
                    'reflection analysis.'
                ),
                'severity': 'high',
                'tags': ['xss', 'injection', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 10,
            },
            {
                'name': 'sql_pattern_detector',
                'display_name': 'SQL Injection Detection',
                'description': 'SQL injection vulnerability scanner using pattern matching and error-based detection.',
                'severity': 'critical',
                'tags': ['sqli', 'injection', 'owasp-top10', 'database'],
                'is_dangerous': False,
                'execution_order': 11,
            },
            {
                'name': 'nosql_injection_detector',
                'display_name': 'NoSQL Injection Detection',
                'description': 'NoSQL injection testing for MongoDB, CouchDB, and other NoSQL databases.',
                'severity': 'high',
                'tags': ['nosql', 'injection', 'database'],
                'is_dangerous': False,
                'execution_order': 12,
            },
            {
                'name': 'command_injection_detector',
                'display_name': 'Command Injection Detection',
                'description': 'OS command injection vulnerability scanner.',
                'severity': 'critical',
                'tags': ['command-injection', 'rce', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 13,
            },
            {
                'name': 'lfi_detector',
                'display_name': 'Local File Inclusion (LFI)',
                'description': 'Local File Inclusion vulnerability detection with path traversal testing.',
                'severity': 'high',
                'tags': ['lfi', 'file-inclusion', 'path-traversal'],
                'is_dangerous': False,
                'execution_order': 14,
            },
            {
                'name': 'ssti_detector',
                'display_name': 'Server-Side Template Injection (SSTI)',
                'description': (
                    'Template injection vulnerability scanner for Jinja2, Twig, Freemarker, and other engines.'
                ),
                'severity': 'critical',
                'tags': ['ssti', 'injection', 'rce'],
                'is_dangerous': False,
                'execution_order': 15,
            },
            {
                'name': 'xxe_detector',
                'display_name': 'XML External Entity (XXE)',
                'description': 'XXE vulnerability detection with file disclosure and SSRF testing.',
                'severity': 'high',
                'tags': ['xxe', 'xml', 'ssrf', 'file-disclosure'],
                'is_dangerous': False,
                'execution_order': 16,
            },

            # SSRF Detectors
            {
                'name': 'ssrf_detector',
                'display_name': 'SSRF Pattern Detection',
                'description': 'Server-Side Request Forgery (SSRF) vulnerability scanner using pattern matching.',
                'severity': 'high',
                'tags': ['ssrf', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 20,
            },
            {
                'name': 'advanced_ssrf_detector',
                'display_name': 'Advanced SSRF Detection',
                'description': 'Advanced SSRF testing with protocol smuggling and bypass techniques.',
                'severity': 'high',
                'tags': ['ssrf', 'advanced'],
                'is_dangerous': False,
                'execution_order': 21,
            },
            {
                'name': 'ssrf_oob_detector',
                'display_name': 'SSRF Out-of-Band Detection',
                'description': 'SSRF detection using out-of-band callbacks (Interactsh).',
                'severity': 'high',
                'tags': ['ssrf', 'oob', 'interactsh'],
                'is_dangerous': False,
                'requires_oob': True,
                'execution_order': 22,
            },

            # Security Headers & CORS
            {
                'name': 'security_headers_detector',
                'display_name': 'Security Headers Analysis',
                'description': 'Analyze HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).',
                'severity': 'medium',
                'tags': ['headers', 'security-headers', 'configuration'],
                'is_dangerous': False,
                'execution_order': 30,
            },
            {
                'name': 'cors_detector',
                'display_name': 'CORS Misconfiguration',
                'description': 'Cross-Origin Resource Sharing (CORS) misconfiguration detection.',
                'severity': 'medium',
                'tags': ['cors', 'configuration', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 31,
            },
            {
                'name': 'csrf_detector',
                'display_name': 'CSRF Detection',
                'description': 'Cross-Site Request Forgery (CSRF) vulnerability detection.',
                'severity': 'medium',
                'tags': ['csrf', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 32,
            },
            {
                'name': 'header_injection_detector',
                'display_name': 'Header Injection',
                'description': 'HTTP header injection and CRLF injection detection.',
                'severity': 'medium',
                'tags': ['header-injection', 'crlf'],
                'is_dangerous': False,
                'execution_order': 33,
            },

            # API & GraphQL
            {
                'name': 'graphql_detector',
                'display_name': 'GraphQL Security',
                'description': 'GraphQL endpoint detection and introspection.',
                'severity': 'info',
                'tags': ['graphql', 'api'],
                'is_dangerous': False,
                'execution_order': 40,
            },
            {
                'name': 'graphql_injection_detector',
                'display_name': 'GraphQL Injection',
                'description': 'GraphQL injection and mutation testing.',
                'severity': 'high',
                'tags': ['graphql', 'api', 'injection'],
                'is_dangerous': False,
                'execution_order': 41,
            },
            {
                'name': 'api_security_detector',
                'display_name': 'API Security Scanner',
                'description': 'REST API security testing including authentication, rate limiting, and data exposure.',
                'severity': 'medium',
                'tags': ['api', 'rest', 'security'],
                'is_dangerous': False,
                'execution_order': 42,
            },

            # Authentication & Authorization
            {
                'name': 'jwt_detector',
                'display_name': 'JWT Vulnerability Scanner',
                'description': 'JSON Web Token (JWT) security testing.',
                'severity': 'high',
                'tags': ['jwt', 'authentication', 'api'],
                'is_dangerous': False,
                'execution_order': 50,
            },
            {
                'name': 'jwt_vulnerability_scanner',
                'display_name': 'Advanced JWT Testing',
                'description': 'Advanced JWT vulnerability detection including algorithm confusion and key cracking.',
                'severity': 'high',
                'tags': ['jwt', 'authentication', 'advanced'],
                'is_dangerous': False,
                'execution_order': 51,
            },
            {
                'name': 'oauth_detector',
                'display_name': 'OAuth Misconfiguration',
                'description': 'OAuth 2.0 implementation vulnerability detection.',
                'severity': 'high',
                'tags': ['oauth', 'authentication'],
                'is_dangerous': False,
                'execution_order': 52,
            },
            {
                'name': 'auth_bypass_detector',
                'display_name': 'Authentication Bypass',
                'description': 'Authentication bypass vulnerability scanner.',
                'severity': 'critical',
                'tags': ['auth-bypass', 'authentication'],
                'is_dangerous': False,
                'execution_order': 53,
            },
            {
                'name': 'idor_detector',
                'display_name': 'IDOR Detection',
                'description': 'Insecure Direct Object Reference (IDOR) vulnerability detection.',
                'severity': 'high',
                'tags': ['idor', 'authorization', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 54,
            },

            # File & Upload Testing
            {
                'name': 'file_upload_detector',
                'display_name': 'File Upload Vulnerability',
                'description': 'File upload security testing including extension bypass and content validation.',
                'severity': 'high',
                'tags': ['file-upload', 'rce'],
                'is_dangerous': False,
                'execution_order': 60,
            },
            {
                'name': 'dir_listing_detector',
                'display_name': 'Directory Listing',
                'description': 'Directory listing and path disclosure detection.',
                'severity': 'low',
                'tags': ['directory-listing', 'information-disclosure'],
                'is_dangerous': False,
                'execution_order': 61,
            },

            # Information Disclosure
            {
                'name': 'secret_detector',
                'display_name': 'Secret & Credential Detection',
                'description': 'Detect exposed API keys, passwords, tokens, and credentials.',
                'severity': 'high',
                'tags': ['secrets', 'credentials', 'information-disclosure'],
                'is_dangerous': False,
                'execution_order': 70,
            },
            {
                'name': 'reflection_detector',
                'display_name': 'Parameter Reflection',
                'description': 'Detect reflected parameters that could lead to XSS or other attacks.',
                'severity': 'info',
                'tags': ['reflection', 'xss'],
                'is_dangerous': False,
                'execution_order': 71,
            },

            # Advanced Attacks
            {
                'name': 'prototype_pollution_detector',
                'display_name': 'Prototype Pollution',
                'description': 'JavaScript prototype pollution vulnerability detection.',
                'severity': 'high',
                'tags': ['prototype-pollution', 'javascript'],
                'is_dangerous': False,
                'execution_order': 80,
            },
            {
                'name': 'cache_poisoning_detector',
                'display_name': 'Cache Poisoning',
                'description': 'Web cache poisoning vulnerability detection.',
                'severity': 'medium',
                'tags': ['cache-poisoning'],
                'is_dangerous': False,
                'execution_order': 81,
            },
            {
                'name': 'race_condition_detector',
                'display_name': 'Race Condition',
                'description': 'Race condition vulnerability detection in critical operations.',
                'severity': 'high',
                'tags': ['race-condition', 'concurrency'],
                'is_dangerous': False,
                'execution_order': 82,
            },
            {
                'name': 'open_redirect_detector',
                'display_name': 'Open Redirect',
                'description': 'Open redirect vulnerability detection.',
                'severity': 'medium',
                'tags': ['open-redirect', 'owasp-top10'],
                'is_dangerous': False,
                'execution_order': 83,
            },

            # Reconnaissance
            {
                'name': 'subdomain_takeover_detector',
                'display_name': 'Subdomain Takeover',
                'description': 'Detect subdomains vulnerable to takeover attacks.',
                'severity': 'high',
                'tags': ['subdomain-takeover', 'dns', 'reconnaissance'],
                'is_dangerous': False,
                'execution_order': 90,
            },
            {
                'name': 'subfinder_detector',
                'display_name': 'Subfinder — Subdomain Enumeration',
                'description': 'Passive subdomain discovery using subfinder.',
                'severity': 'info',
                'tags': ['recon', 'subdomains', 'passive'],
                'is_dangerous': False,
                'execution_order': 91,
            },
            {
                'name': 'nmap_detector',
                'display_name': 'Nmap — Port & Service Scanner',
                'description': (
                    'Port scanning and service version detection using nmap. '
                    'Supports quick, service, scripts, vuln, full and custom scan presets.'
                ),
                'severity': 'medium',
                'tags': ['recon', 'nmap', 'portscan', 'service-detection'],
                'is_dangerous': False,
                'execution_order': 91,
            },
            {
                'name': 'amass_detector',
                'display_name': 'Amass — Subdomain Enumeration',
                'description': 'Passive subdomain discovery using amass.',
                'severity': 'info',
                'tags': ['recon', 'subdomains', 'passive'],
                'is_dangerous': False,
                'execution_order': 92,
            },
            {
                'name': 'httpx_detector',
                'display_name': 'HTTPX — Live Host Probing',
                'description': 'Probe discovered subdomains for live HTTP services, titles and technologies.',
                'severity': 'info',
                'tags': ['recon', 'httpx', 'probing'],
                'is_dangerous': False,
                'execution_order': 93,
            },
            {
                'name': 'katana_detector',
                'display_name': 'Katana — Web Crawler',
                'description': 'Crawl target with katana to discover endpoints, JS files and API paths.',
                'severity': 'low',
                'tags': ['recon', 'crawling', 'katana'],
                'is_dangerous': False,
                'execution_order': 94,
            },
            {
                'name': 'gf_pattern_detector',
                'display_name': 'GF Patterns — Parameter Classification',
                'description': 'Classify URL parameters by vulnerability category (idor/ssrf/xss/sqli/lfi/rce).',
                'severity': 'low',
                'tags': ['recon', 'parameters', 'gf-patterns'],
                'is_dangerous': False,
                'execution_order': 95,
            },
            {
                'name': 'dalfox_detector',
                'display_name': 'Dalfox — XSS Scanner',
                'description': 'Fast and accurate XSS scanning using dalfox.',
                'severity': 'high',
                'tags': ['xss', 'dalfox', 'injection'],
                'is_dangerous': False,
                'execution_order': 96,
            },
            {
                'name': 'ffuf_idor_detector',
                'display_name': 'FFUF — IDOR Fuzzing',
                'description': 'Fuzz numeric ID parameters to detect Insecure Direct Object References.',
                'severity': 'high',
                'tags': ['idor', 'fuzzing', 'ffuf'],
                'is_dangerous': True,
                'execution_order': 97,
            },

            # Mobile Security
            {
                'name': 'apk_analyzer_detector',
                'display_name': 'APK Analyzer — Android Static Analysis',
                'description': (
                    'Static analysis of Android APK files: dangerous permissions, hardcoded secrets, '
                    'weak crypto, debug flags, exported components and cleartext traffic.'
                ),
                'severity': 'high',
                'tags': ['mobile', 'android', 'apk', 'static-analysis'],
                'is_dangerous': False,
                'execution_order': 98,
            },
            {
                'name': 'ios_scanner_detector',
                'display_name': 'iOS Scanner — IPA Static Analysis',
                'description': (
                    'Static analysis of iOS IPA files: ATS configuration, hardcoded secrets, '
                    'insecure data storage, weak crypto, and binary protections.'
                ),
                'severity': 'high',
                'tags': ['mobile', 'ios', 'ipa', 'static-analysis'],
                'is_dangerous': False,
                'execution_order': 99,
            },

            # CVE & Vulnerability Database
            {
                'name': 'cve_database_detector',
                'display_name': 'CVE Database Scanner',
                'description': 'Scan for known CVEs and vulnerabilities from database.',
                'severity': 'critical',
                'tags': ['cve', 'vulnerability-database'],
                'is_dangerous': False,
                'execution_order': 100,
            },

            # Fuzzing & Brute Force (DANGEROUS - Enterprise only)
            {
                'name': 'fuzz_detector',
                'display_name': 'Smart Fuzzing',
                'description': 'Intelligent fuzzing for parameter discovery and input validation testing.',
                'severity': 'medium',
                'tags': ['fuzzing', 'testing'],
                'is_dangerous': True,
                'execution_order': 200,
            },
            {
                'name': 'brute_force_detector',
                'display_name': 'Brute Force Testing',
                'description': (
                    'Brute force testing for authentication endpoints and admin panels. DANGEROUS - high '
                    'request volume.'
                ),
                'severity': 'high',
                'tags': ['brute-force', 'authentication'],
                'is_dangerous': True,
                'execution_order': 201,
            },
            {
                'name': 'rate_limit_bypass_detector',
                'display_name': 'Rate Limit Bypass',
                'description': 'Test for rate limiting bypass vulnerabilities.',
                'severity': 'medium',
                'tags': ['rate-limiting', 'bypass'],
                'is_dangerous': True,
                'execution_order': 202,
            },

            # Utility detectors
            {
                'name': 'interactsh_client',
                'display_name': 'Interactsh OOB Client',
                'description': 'Out-of-band callback detection using Interactsh.',
                'severity': 'info',
                'tags': ['oob', 'utility'],
                'is_dangerous': False,
                'requires_oob': True,
                'execution_order': 300,
            },
            {
                'name': 'injector',
                'display_name': 'Payload Injector',
                'description': 'Generic payload injection utility.',
                'severity': 'info',
                'tags': ['utility', 'injection'],
                'is_dangerous': True,
                'execution_order': 301,
            },
        ]

        detectors = {}
        for data in detectors_data:
            detector, created = DetectorConfig.objects.update_or_create(
                name=data['name'],
                defaults=data
            )
            detectors[data['name']] = detector
            dangerous_mark = ' 🔴 DANGEROUS' if data.get('is_dangerous') else ''
            status = '✨' if created else '♻️ '
            self.stdout.write(f'{status} {detector.display_name}{dangerous_mark}')

        # Auto-discover any detectors missing from the hardcoded list.
        discovered = self._discover_detector_module_names()
        for name in discovered:
            if name in detectors:
                continue

            severity, tags = self._infer_severity_and_tags(name)
            defaults = {
                'name': name,
                'display_name': self._humanize_detector_name(name),
                'description': f'Auto-generated metadata for detector "{name}".',
                'severity': severity,
                'tags': tags,
                'is_dangerous': bool('nuclei' in name or 'brute_force' in name),
                'execution_order': 200,
            }
            detector, created = DetectorConfig.objects.update_or_create(
                name=name,
                defaults=defaults,
            )
            detectors[name] = detector
            status = '✨' if created else '♻️ '
            self.stdout.write(f'{status} {detector.display_name} (auto)')

        return detectors

    def assign_to_categories(self, categories, detectors):
        """Assign detectors to appropriate categories"""

        def plan_category_memberships(detector_name: str) -> set:
            n = (detector_name or '').lower()
            membership: set[str] = set()

            recon_kw = (
                'recon', 'osint', 'secret', 'backup', 'subdomain', 'takeover',
                'dir_listing', 'file_list', 'old_domain', 'domain_hunter', 'js_file',
                'github', 'simple_file_list',
                'subfinder', 'amass', 'httpx', 'katana', 'gf_pattern', 'nmap',
            )
            api_kw = ('api', 'graphql', 'jwt', 'oauth', 'idor', 'rate_limit')
            vuln_kw = ('cve', 'nuclei', 'vulnerability')
            mobile_kw = ('mobile', 'android', 'ios', 'apk', 'ipa')

            if any(k in n for k in recon_kw):
                membership.add('recon')
            if any(k in n for k in api_kw):
                membership.add('api')
            if any(k in n for k in vuln_kw):
                membership.add('vuln')
            if any(k in n for k in mobile_kw):
                membership.add('mobile')

            # Web is the default bucket; many detectors are web-facing.
            webish = (
                'xss', 'sql', 'nosql', 'command_injection', 'lfi', 'ssti', 'xxe',
                'csrf', 'cors', 'ssrf', 'open_redirect', 'security_headers',
                'reflection', 'file_upload', 'prototype_pollution',
                'cache_poisoning', 'header_injection', 'brute_force', 'fuzz',
                'race_condition', 'dalfox', 'ffuf',
            )
            if any(k in n for k in webish):
                membership.add('web')

            if not membership:
                membership.add('web')

            # Known cross-category overlaps
            if 'cors' in n:
                membership.add('api')
            if 'security_headers' in n:
                membership.add('recon')
            if 'secret' in n:
                membership.add('vuln')

            return membership

        assignments: dict[str, set[str]] = {
            'recon': set(),
            'web': set(),
            'api': set(),
            'vuln': set(),
            'mobile': set(),
        }

        for detector_name in detectors.keys():
            for cat in plan_category_memberships(detector_name):
                if cat in assignments:
                    assignments[cat].add(detector_name)

        for cat_name, detector_names in assignments.items():
            if cat_name not in categories:
                continue
            category = categories[cat_name]
            category.detectors.clear()
            for detector_name in sorted(detector_names):
                detector = detectors.get(detector_name)
                if detector:
                    category.detectors.add(detector)

            self.stdout.write(f'   ➡️  {category.display_name}: {len(detector_names)} detectors assigned')

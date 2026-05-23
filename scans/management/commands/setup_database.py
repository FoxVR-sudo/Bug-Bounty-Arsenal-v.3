"""
Management command to populate database with plans, scan categories, and detector configurations.
Usage: python manage.py setup_database
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from subscriptions.models import Plan
from scans.category_models import ScanCategory, DetectorConfig


class Command(BaseCommand):
    help = 'Populate database with plans, scan categories, and detector configurations'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🚀 Setting up BugBounty Arsenal Database...\n'))

        with transaction.atomic():
            # Create Plans
            self.create_plans()

            # Create Scan Categories
            self.create_scan_categories()

            # Create Detector Configurations
            self.create_detector_configs()

            # Map Detectors to Categories
            self.map_detectors_to_categories()

        self.stdout.write(self.style.SUCCESS('\n✅ Database setup complete!'))
        self.print_summary()

    def create_plans(self):
        """Create subscription plans"""
        self.stdout.write('Creating subscription plans...')

        plans_data = [
            {
                'name': 'free',
                'display_name': 'Free',
                'description': 'Perfect for getting started with bug bounty hunting',
                'price': 0.00,
                'scans_per_day': 3,
                'scans_per_month': 30,
                'concurrent_scans': 1,
                'storage_limit_mb': 100,
                'retention_days': 7,
                'allow_dangerous_tools': False,
                'allow_teams': False,
                'max_team_members': 0,
                'allow_integrations': False,
                'max_integrations': 0,
                'features': ['Recon Scan', 'Web Scan', 'Basic Reports', 'Community Support'],
                'is_active': True,
                'order': 1
            },
            {
                'name': 'pro',
                'display_name': 'Pro',
                'description': 'For professional bug bounty hunters and security researchers',
                'price': 49.00,
                'scans_per_day': 100,
                'scans_per_month': 1000,
                'concurrent_scans': 5,
                'storage_limit_mb': 5000,
                'retention_days': 30,
                'allow_dangerous_tools': False,
                'allow_teams': True,
                'max_team_members': 5,
                'allow_integrations': True,
                'max_integrations': 5,
                'features': [
                    'All Free features',
                    'Recon + Web + API + Vuln + Mobile Scans',
                    'Advanced Reports',
                    'Team Collaboration (5 members)',
                    'Integrations (Slack, Jira, etc.)',
                    'Priority Support',
                    '30-day retention'
                ],
                'is_active': True,
                'is_popular': True,
                'order': 2
            },
            {
                'name': 'enterprise',
                'display_name': 'Enterprise',
                'description': 'For security teams and companies requiring unlimited scanning',
                'price': 99.00,
                'scans_per_day': -1,  # Unlimited
                'scans_per_month': -1,  # Unlimited
                'concurrent_scans': 20,
                'storage_limit_mb': 50000,
                'retention_days': 90,
                'allow_dangerous_tools': True,
                'allow_teams': True,
                'max_team_members': 50,
                'allow_integrations': True,
                'max_integrations': -1,  # Unlimited
                'features': [
                    'All Pro features',
                    'Unlimited Scans',
                    'Custom Scan (All 40+ Detectors)',
                    'Dangerous Tools (Nuclei, Custom Payloads)',
                    'Team Collaboration (50 members)',
                    'Unlimited Integrations',
                    'Company Verification',
                    'Dedicated Support',
                    '90-day retention',
                    'Custom SLA'
                ],
                'is_active': True,
                'order': 3
            }
        ]

        for plan_data in plans_data:
            plan, created = Plan.objects.update_or_create(
                name=plan_data['name'],
                defaults=plan_data
            )
            status = 'Created' if created else 'Updated'
            self.stdout.write(f'  ✓ {status} plan: {plan.display_name} (${plan.price}/month)')

    def create_scan_categories(self):
        """Create scan categories"""
        self.stdout.write('\nCreating scan categories...')

        categories_data = [
            {
                'name': 'recon',
                'display_name': 'Reconnaissance Scan',
                'description': (
                    'Subdomain enumeration, DNS records, WHOIS lookup, technology detection, and port scanning'
                ),
                'required_plan': 'free',
                'icon': '🔍',
                'order': 1,
            },
            {
                'name': 'web',
                'display_name': 'Web Application Scan',
                'description': (
                    'XSS, SQL injection, CSRF, CORS, security headers, open redirects, and other web '
                    'vulnerabilities'
                ),
                'required_plan': 'free',
                'icon': '🌐',
                'order': 2,
            },
            {
                'name': 'api',
                'display_name': 'API Security Scan',
                'description': (
                    'GraphQL injection, REST API security, JWT vulnerabilities, OAuth misconfigurations'
                ),
                'required_plan': 'pro',
                'icon': '🔌',
                'order': 3,
            },
            {
                'name': 'vuln',
                'display_name': 'Vulnerability Scan',
                'description': (
                    'CVE detection, known vulnerabilities, version detection, and security patch analysis'
                ),
                'required_plan': 'pro',
                'icon': '🔓',
                'order': 4,
            },
            {
                'name': 'mobile',
                'display_name': 'Mobile Security Scan',
                'description': (
                    'Android and iOS application security testing, API endpoint discovery'
                ),
                'required_plan': 'pro',
                'icon': '📱',
                'order': 5,
            },
            {
                'name': 'custom',
                'display_name': 'Custom Scan (All Tools)',
                'description': (
                    'Run ALL 40+ detectors including dangerous tools, nuclei templates, and custom payloads'
                ),
                'required_plan': 'enterprise',
                'icon': '⚡',
                'order': 6,
            },
        ]

        for cat_data in categories_data:
            category, created = ScanCategory.objects.update_or_create(
                name=cat_data['name'],
                defaults=cat_data
            )
            status = 'Created' if created else 'Updated'
            self.stdout.write(f'  ✓ {status} category: {category.display_name} ({category.required_plan}+)')

    def create_detector_configs(self):
        """Create detector configurations"""
        self.stdout.write('\nCreating detector configurations...')

        detectors_data = [
            # Web Security Detectors
            {
                'name': 'xss_pattern_detector',
                'display_name': 'XSS Pattern Detection',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'sql_pattern_detector',
                'display_name': 'SQL Injection Detection',
                'severity': 'critical',
                'is_dangerous': False,
            },
            {
                'name': 'cors_detector',
                'display_name': 'CORS Misconfiguration',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'csrf_detector',
                'display_name': 'CSRF Vulnerability',
                'severity': 'medium',
                'is_dangerous': False,
            },
            {
                'name': 'security_headers_detector',
                'display_name': 'Security Headers',
                'severity': 'low',
                'is_dangerous': False,
            },
            {
                'name': 'open_redirect_detector',
                'display_name': 'Open Redirect',
                'severity': 'medium',
                'is_dangerous': False,
            },
            {
                'name': 'lfi_detector',
                'display_name': 'Local File Inclusion',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'ssti_detector',
                'display_name': 'Server-Side Template Injection',
                'severity': 'critical',
                'is_dangerous': False,
            },
            {
                'name': 'xxe_detector',
                'display_name': 'XML External Entity (XXE)',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'prototype_pollution_detector',
                'display_name': 'Prototype Pollution',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'header_injection_detector',
                'display_name': 'HTTP Header Injection',
                'severity': 'medium',
                'is_dangerous': False,
            },
            {
                'name': 'command_injection_detector',
                'display_name': 'Command Injection',
                'severity': 'critical',
                'is_dangerous': False,
            },
            {
                'name': 'nosql_injection_detector',
                'display_name': 'NoSQL Injection',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'cache_poisoning_detector',
                'display_name': 'Web Cache Poisoning',
                'severity': 'medium',
                'is_dangerous': False,
            },

            # API Security Detectors
            {
                'name': 'graphql_detector',
                'display_name': 'GraphQL Security',
                'severity': 'medium',
                'is_dangerous': False,
            },
            {
                'name': 'graphql_injection_detector',
                'display_name': 'GraphQL Injection',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'jwt_detector',
                'display_name': 'JWT Vulnerabilities',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'oauth_detector',
                'display_name': 'OAuth Misconfiguration',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'api_security_detector',
                'display_name': 'API Security',
                'severity': 'medium',
                'is_dangerous': False,
            },

            # Advanced Detectors
            {
                'name': 'idor_detector',
                'display_name': 'IDOR (Insecure Direct Object Reference)',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'auth_bypass_detector',
                'display_name': 'Authentication Bypass',
                'severity': 'critical',
                'is_dangerous': False,
            },
            {
                'name': 'ssrf_detector',
                'display_name': 'Server-Side Request Forgery',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'advanced_ssrf_detector',
                'display_name': 'Advanced SSRF',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'ssrf_oob_detector',
                'display_name': 'SSRF Out-of-Band',
                'severity': 'high',
                'is_dangerous': False,
                'requires_oob': True,
            },
            {
                'name': 'race_condition_detector',
                'display_name': 'Race Condition',
                'severity': 'medium',
                'is_dangerous': False,
            },
            {
                'name': 'rate_limit_bypass_detector',
                'display_name': 'Rate Limit Bypass',
                'severity': 'medium',
                'is_dangerous': False,
            },

            # Reconnaissance Detectors
            {
                'name': 'subdomain_takeover_detector',
                'display_name': 'Subdomain Takeover',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'dir_listing_detector',
                'display_name': 'Directory Listing',
                'severity': 'low',
                'is_dangerous': False,
            },
            {
                'name': 'secret_detector',
                'display_name': 'Secret/API Key Detection',
                'severity': 'high',
                'is_dangerous': False,
            },
            {
                'name': 'reflection_detector',
                'display_name': 'Input Reflection',
                'severity': 'info',
                'is_dangerous': False,
            },

            # Dangerous Tools (Enterprise only)
            {
                'name': 'fuzz_detector',
                'display_name': 'Advanced Fuzzing',
                'severity': 'high',
                'is_dangerous': True,
            },
            {
                'name': 'file_upload_detector',
                'display_name': 'File Upload Vulnerabilities',
                'severity': 'high',
                'is_dangerous': True,
            },
            {
                'name': 'brute_force_detector',
                'display_name': 'Brute Force Testing',
                'severity': 'medium',
                'is_dangerous': True,
            },
            {
                'name': 'basic_param_fuzzer',
                'display_name': 'Parameter Fuzzing',
                'severity': 'medium',
                'is_dangerous': True,
            },
        ]

        for detector_data in detectors_data:
            detector, created = DetectorConfig.objects.update_or_create(
                name=detector_data['name'],
                defaults={
                    'display_name': detector_data['display_name'],
                    'description': f"Detects {detector_data['display_name'].lower()} vulnerabilities",
                    'severity': detector_data['severity'],
                    'is_dangerous': detector_data.get('is_dangerous', False),
                    'requires_oob': detector_data.get('requires_oob', False),
                    'is_active': True
                }
            )
            status = 'Created' if created else 'Updated'
            dangerous_flag = ' [ENTERPRISE]' if detector.is_dangerous else ''
            self.stdout.write(f'  ✓ {status} detector: {detector.display_name}{dangerous_flag}')

    def map_detectors_to_categories(self):
        """Map detectors to scan categories"""
        self.stdout.write('\nMapping detectors to categories...')

        # Get all objects
        categories = {cat.name: cat for cat in ScanCategory.objects.all()}
        detectors = {det.name: det for det in DetectorConfig.objects.all()}

        # Category mappings
        mappings = {
            'recon': [
                'subdomain_takeover_detector',
                'dir_listing_detector',
                'secret_detector',
                'reflection_detector',
                'security_headers_detector',
            ],
            'web': [
                'xss_pattern_detector',
                'sql_pattern_detector',
                'cors_detector',
                'csrf_detector',
                'security_headers_detector',
                'open_redirect_detector',
                'lfi_detector',
                'ssti_detector',
                'xxe_detector',
                'prototype_pollution_detector',
                'header_injection_detector',
                'command_injection_detector',
                'nosql_injection_detector',
                'cache_poisoning_detector',
                'reflection_detector',
                'dir_listing_detector',
            ],
            'api': [
                'graphql_detector',
                'graphql_injection_detector',
                'jwt_detector',
                'oauth_detector',
                'api_security_detector',
                'idor_detector',
                'auth_bypass_detector',
                'rate_limit_bypass_detector',
            ],
            'vuln': [
                'sql_pattern_detector',
                'xss_pattern_detector',
                'xxe_detector',
                'ssti_detector',
                'command_injection_detector',
                'lfi_detector',
                'ssrf_detector',
                'advanced_ssrf_detector',
                'ssrf_oob_detector',
            ],
            'mobile': [
                'api_security_detector',
                'jwt_detector',
                'oauth_detector',
                'secret_detector',
                'idor_detector',
            ],
            'custom': list(detectors.keys()),  # All detectors
        }

        for category_name, detector_names in mappings.items():
            if category_name not in categories:
                continue

            category = categories[category_name]

            for detector_name in detector_names:
                if detector_name in detectors:
                    detector = detectors[detector_name]
                    category.detectors.add(detector)

            # Update detector count
            category.update_detector_count()

            self.stdout.write(f'  ✓ Mapped {category.detector_count} detectors to {category.display_name}')

    def print_summary(self):
        """Print setup summary"""
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('DATABASE SETUP SUMMARY'))
        self.stdout.write('=' * 60)

        # Plans
        plans = Plan.objects.all()
        self.stdout.write(f'\n📋 Plans: {plans.count()}')
        for plan in plans:
            self.stdout.write(f'   • {plan.display_name}: ${plan.price}/month')
            self.stdout.write(f'     Scans: {plan.scans_per_day}/day, {plan.scans_per_month}/month')

        # Categories
        categories = ScanCategory.objects.all()
        self.stdout.write(f'\n📂 Scan Categories: {categories.count()}')
        for cat in categories:
            self.stdout.write(
                f'   {cat.icon} {cat.display_name}: {cat.detector_count} detectors ({cat.required_plan}+)'
            )

        # Detectors
        detectors = DetectorConfig.objects.all()
        dangerous_count = detectors.filter(is_dangerous=True).count()
        self.stdout.write(f'\n🔍 Detectors: {detectors.count()} total')
        self.stdout.write(f'   • Safe detectors: {detectors.count() - dangerous_count}')
        self.stdout.write(f'   • Dangerous tools: {dangerous_count} (Enterprise only)')

        self.stdout.write('\n' + '=' * 60)

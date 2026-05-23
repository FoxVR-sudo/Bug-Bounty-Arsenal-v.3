"""
Management command to populate initial data for production
"""
from django.core.management.base import BaseCommand
from subscriptions.models import Plan
from scans.models import ScanCategory


class Command(BaseCommand):
    help = 'Populate initial data for production'

    def handle(self, *args, **kwargs):
        self.stdout.write('Creating initial subscription plans...')

        # Create Plans
        free_plan, created = Plan.objects.get_or_create(
            name='Free',
            defaults={
                'price': 0.00,
                'stripe_price_id': '',
                'description': 'Basic security scanning',
                'features': {
                    'max_scans_per_month': 5,
                    'max_concurrent_scans': 1,
                    'scan_timeout_minutes': 30,
                    'features': ['Basic vulnerability detection', 'PDF reports']
                }
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'Created plan: {free_plan.name}'))

        pro_plan, created = Plan.objects.get_or_create(
            name='Pro',
            defaults={
                'price': 19.00,
                'stripe_price_id': 'price_1SlSBg5oSlrc0LTCf3b4a61O',
                'description': 'Advanced security scanning',
                'features': {
                    'max_scans_per_month': 50,
                    'max_concurrent_scans': 3,
                    'scan_timeout_minutes': 60,
                    'features': ['Advanced detectors', 'Priority support', 'API access']
                }
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'Created plan: {pro_plan.name}'))

        enterprise_plan, created = Plan.objects.get_or_create(
            name='Enterprise',
            defaults={
                'price': 99.00,
                'stripe_price_id': 'price_1SlSBh5oSlrc0LTCRcB7kshD',
                'description': 'Enterprise-grade security',
                'features': {
                    'max_scans_per_month': -1,
                    'max_concurrent_scans': 10,
                    'scan_timeout_minutes': 120,
                    'features': ['All detectors', 'Dedicated support', 'Custom integrations', 'Team collaboration']
                }
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'Created plan: {enterprise_plan.name}'))

        # Create Scan Categories
        self.stdout.write('Creating scan categories...')

        categories_data = [{'name': '0-Day Hunting',
                            'slug': '0day-hunting',
                            'description': 'Advanced zero-day vulnerability detection',
                            'icon': '🎯',
                            'available_detectors': ['advanced_ssrf_detector',
                                                    'cache_poisoning_detector',
                                                    'prototype_pollution_detector',
                                                    'race_condition_detector',
                                                    'rate_limit_bypass_detector',
                                                    'header_injection_detector']},
                           {'name': 'Web Application',
                            'slug': 'web-application',
                            'description': 'Standard web vulnerability scanning',
                            'icon': '🌐',
                            'available_detectors': ['xss_pattern_detector',
                                                    'sql_pattern_detector',
                                                    'csrf_detector',
                                                    'cors_detector',
                                                    'open_redirect_detector',
                                                    'lfi_detector']},
                           {'name': 'API Security',
                            'slug': 'api-security',
                            'description': 'API-specific security tests',
                            'icon': '🔌',
                            'available_detectors': ['api_security_detector',
                                                    'jwt_detector',
                                                    'graphql_detector',
                                                    'nosql_injection_detector']},
                           {'name': 'Authentication',
                            'slug': 'authentication',
                            'description': 'Authentication and authorization testing',
                            'icon': '🔐',
                            'available_detectors': ['auth_bypass_detector',
                                                    'brute_force_detector',
                                                    'idor_detector',
                                                    'jwt_vulnerability_scanner']},
                           {'name': 'Injection Attacks',
                            'slug': 'injection-attacks',
                            'description': 'All types of injection vulnerabilities',
                            'icon': '💉',
                            'available_detectors': ['sql_pattern_detector',
                                                    'command_injection_detector',
                                                    'xxe_detector',
                                                    'ssti_detector',
                                                    'nosql_injection_detector']}]

        for cat_data in categories_data:
            category, created = ScanCategory.objects.get_or_create(
                slug=cat_data['slug'],
                defaults=cat_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'Created category: {category.name}'))

        self.stdout.write(self.style.SUCCESS('Initial data populated successfully!'))

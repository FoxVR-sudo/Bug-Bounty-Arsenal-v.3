"""
Management command to create/update subscription plans
"""
from django.core.management.base import BaseCommand
from django.conf import settings
from subscriptions.models import Plan


class Command(BaseCommand):
    help = 'Create or update subscription plans with correct settings'

    def handle(self, *args, **options):
        pro_monthly = str(getattr(settings, 'STRIPE_PRICE_PRO_MONTHLY', '') or '').strip()
        pro_yearly = str(getattr(settings, 'STRIPE_PRICE_PRO_YEARLY', '') or '').strip()
        enterprise_monthly = str(getattr(settings, 'STRIPE_PRICE_ENTERPRISE_MONTHLY', '') or '').strip()
        enterprise_yearly = str(getattr(settings, 'STRIPE_PRICE_ENTERPRISE_YEARLY', '') or '').strip()

        plans_data = [
            {
                'name': 'free',
                'display_name': 'Free',
                'description': 'Perfect for getting started with basic security scanning',
                'price': 0.00,
                'price_yearly': 0.00,
                'scans_per_day': 3,
                'scans_per_month': 10,
                'concurrent_scans': 1,
                'storage_limit_mb': 100,
                'retention_days': 7,
                'features': [
                    '3 scans per day',
                    '10 scans per month',
                    'Web & Recon basics',
                ],
                'is_popular': False,
                'order': 1,
            },
            {
                'name': 'pro',
                'display_name': 'Pro',
                'description': 'For professionals requiring comprehensive security testing',
                'price': 19.00,
                # Two months free on yearly billing (pay for 10 months)
                'price_yearly': 190.00,
                **({'stripe_price_id_monthly': pro_monthly} if pro_monthly else {}),
                **({'stripe_price_id_yearly': pro_yearly} if pro_yearly else {}),
                'scans_per_day': 100,
                'scans_per_month': 500,
                'concurrent_scans': 5,
                'storage_limit_mb': 2048,
                'retention_days': 90,
                'features': [
                    '100 scans per day',
                    '500 scans per month',
                    'Advanced categories',
                ],
                'is_popular': True,
                'order': 2,
            },
            {
                'name': 'enterprise',
                'display_name': 'Enterprise',
                'description': 'For organizations with unlimited scanning needs',
                'price': 99.00,
                # Two months free on yearly billing (pay for 10 months)
                'price_yearly': 990.00,
                **({'stripe_price_id_monthly': enterprise_monthly} if enterprise_monthly else {}),
                **({'stripe_price_id_yearly': enterprise_yearly} if enterprise_yearly else {}),
                'scans_per_day': -1,
                'scans_per_month': -1,
                'concurrent_scans': 10,
                'storage_limit_mb': 10240,
                'retention_days': 365,
                'allow_dangerous_tools': True,
                'allow_teams': True,
                'allow_integrations': True,
                'features': [
                    'Unlimited scans',
                    'All categories',
                    'Dangerous tools',
                ],
                'is_popular': False,
                'order': 3,
            },
        ]

        for plan_data in plans_data:
            plan, created = Plan.objects.update_or_create(
                name=plan_data['name'],
                defaults=plan_data
            )

            action = 'Created' if created else 'Updated'
            self.stdout.write(
                self.style.SUCCESS(f'{action} plan: {plan.display_name} (${plan.price}/month)')
            )

        self.stdout.write(self.style.SUCCESS('\n✅ All plans configured successfully!'))

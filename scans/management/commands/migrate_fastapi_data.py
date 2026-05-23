"""
Django management command to migrate data from FastAPI backup database.

Usage:
    python manage.py migrate_fastapi_data [--backup-db PATH] [--dry-run]
"""

import sqlite3
import json
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from users.models import User
from scans.models import Scan
from usage.models import Plan, Subscription


class Command(BaseCommand):
    help = 'Migrate data from FastAPI backup database to Django database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--backup-db',
            type=str,
            default='bugbounty_arsenal_fastapi_backup.db',
            help='Path to FastAPI backup database'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run without saving data'
        )

    def handle(self, *args, **options):
        backup_db_path = options['backup_db']
        dry_run = options['dry_run']

        self.stdout.write(self.style.SUCCESS('\n' + '=' * 60))
        self.stdout.write(self.style.SUCCESS('FastAPI → Django Data Migration'))
        self.stdout.write(self.style.SUCCESS('=' * 60 + '\n'))

        if dry_run:
            self.stdout.write(self.style.WARNING('🔍 DRY RUN MODE\n'))

        try:
            conn = sqlite3.connect(backup_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            stats = {}

            with transaction.atomic():
                # Migrate data
                self.stdout.write('👥 Migrating Users...')
                stats['users'] = self._migrate_users(cursor)

                self.stdout.write('\n📋 Migrating Plans...')
                stats['plans'] = self._migrate_plans(cursor)

                self.stdout.write('\n💳 Migrating Subscriptions...')
                stats['subscriptions'] = self._migrate_subscriptions(cursor)

                self.stdout.write('\n🔍 Migrating Scans...')
                stats['scans'] = self._migrate_scans(cursor)

                if dry_run:
                    raise CommandError('Dry run - no data saved')

            # Summary
            self.stdout.write('\n' + '=' * 60)
            self.stdout.write(self.style.SUCCESS('✅ Migration Summary'))
            self.stdout.write('=' * 60)
            for model, count in stats.items():
                self.stdout.write(f"{model.capitalize()}: {count} migrated")

            conn.close()
            self.stdout.write(self.style.SUCCESS('\n✅ Migration completed!\n'))

        except CommandError:
            raise
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'\n❌ Error: {str(e)}'))
            raise

    def _migrate_users(self, cursor):
        cursor.execute('SELECT * FROM users ORDER BY id')
        count = 0
        self.user_map = {}

        for row in cursor.fetchall():
            r = dict(row)
            user, _ = User.objects.update_or_create(
                email=r['email'],
                defaults={
                    'password': r.get('password_hash', ''),
                    'is_active': bool(r.get('is_active', True)),
                    'is_admin': bool(r.get('is_admin', False)),
                    'is_staff': bool(r.get('is_superuser', False)),
                    'is_superuser': bool(r.get('is_superuser', False)),
                }
            )
            self.user_map[r['id']] = user
            count += 1
            self.stdout.write(f"  ✓ {user.email}")

        return count

    def _migrate_plans(self, cursor):
        cursor.execute('SELECT * FROM plans ORDER BY id')
        count = 0
        self.plan_map = {}

        for row in cursor.fetchall():
            r = dict(row)
            plan, _ = Plan.objects.update_or_create(
                name=r['name'],
                defaults={
                    'display_name': r.get('display_name', r['name']),
                    'price': r.get('price_monthly', 0.0) or 0.0,
                    'limits': json.loads(r.get('limits', '{}')),
                    'features': json.loads(r.get('features', '[]')),
                }
            )
            self.plan_map[r['id']] = plan
            count += 1
            self.stdout.write(f"  ✓ {plan.name}")

        return count

    def _migrate_subscriptions(self, cursor):
        cursor.execute('SELECT * FROM subscriptions ORDER BY id')
        count = 0

        for row in cursor.fetchall():
            r = dict(row)
            user = self.user_map.get(r['user_id'])
            plan = self.plan_map.get(r.get('plan_id'))

            if not user:
                continue

            status_map = {'active': 'active', 'trialing': 'trialing', 'canceled': 'cancelled'}
            status = status_map.get(r.get('status', 'inactive'), 'inactive')

            Subscription.objects.update_or_create(
                user=user,
                defaults={
                    'plan': plan,
                    'status': status,
                    'stripe_customer_id': r.get('stripe_customer_id') or '',
                    'stripe_subscription_id': r.get('stripe_subscription_id') or '',
                }
            )
            count += 1
            self.stdout.write(f"  ✓ Subscription for {user.email}")

        return count

    def _migrate_scans(self, cursor):
        cursor.execute('SELECT * FROM scans ORDER BY id')
        count = 0

        for row in cursor.fetchall():
            r = dict(row)
            user = self.user_map.get(r['user_id'])

            if not user:
                continue

            scan_type_map = {
                'recon': 'reconnaissance',
                'safe': 'web_security',
                'brutal': 'vulnerability',
                'manual': 'web_security',
            }
            scan_type = scan_type_map.get(r.get('mode', 'safe'), 'web_security')

            status_map = {
                'pending': 'pending',
                'running': 'running',
                'completed': 'completed',
                'failed': 'failed',
                'cancelled': 'stopped',
            }
            status = status_map.get(r.get('status', 'completed'), 'completed')

            Scan.objects.create(
                user=user,
                target=r.get('target', 'Unknown'),
                scan_type=scan_type,
                status=status,
                vulnerabilities_found=r.get('vulnerabilities_found', 0),
                report_path=r.get('report_path') or '',
            )
            count += 1

            if count % 10 == 0:
                self.stdout.write(f"  ✓ {count} scans migrated...")

        return count

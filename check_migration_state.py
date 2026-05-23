#!/usr/bin/env python3
"""
Check Django migration state vs actual database schema
"""
import os
import django
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(os.path.join(BASE_DIR, '.env'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.db import connection  # noqa: E402

cursor = connection.cursor()

print("=" * 60)
print("DJANGO MIGRATION TRACKER (django_migrations table)")
print("=" * 60)

try:
    cursor.execute("SELECT app, name FROM django_migrations ORDER BY app, name;")
    rows = cursor.fetchall()

    for app, name in rows:
        print(f"  {app:20s} {name}")

    print(f"\nTotal migration records: {len(rows)}")
except Exception as e:
    print(f"ERROR reading django_migrations: {e}")

print("\n" + "=" * 60)
print("ACTUAL DATABASE TABLES")
print("=" * 60)

try:
    cursor.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
        ORDER BY table_name;
    """)
    tables = cursor.fetchall()

    for (table,) in tables:
        print(f"  {table}")

    print(f"\nTotal tables: {len(tables)}")

    # Check for critical missing tables
    table_names = [t[0] for t in tables]
    critical_tables = ['users', 'auth_user', 'scans_scan', 'subscriptions_subscription']

    print("\n" + "=" * 60)
    print("CRITICAL TABLES CHECK")
    print("=" * 60)

    for table in critical_tables:
        status = "✓ EXISTS" if table in table_names else "✗ MISSING"
        print(f"  {table:30s} {status}")

except Exception as e:
    print(f"ERROR reading tables: {e}")

print("\n" + "=" * 60)
print("DIAGNOSIS")
print("=" * 60)

if len(rows) > 0 and len(tables) <= 3:
    print("⚠️  MIGRATION STATE CORRUPTION DETECTED")
    print("   Django thinks migrations are applied but tables don't exist.")
    print("\n   SOLUTION: Clear django_migrations table and re-run migrations")
    print("   Run: python reset_migrations.py")
elif len(rows) == 0 and len(tables) <= 3:
    print("✓ Clean state - no migrations applied yet")
    print("\n   SOLUTION: Run migrations normally")
    print("   Run: python manage.py migrate")
else:
    print("✓ Database appears healthy")
    print(f"   {len(rows)} migrations applied, {len(tables)} tables exist")

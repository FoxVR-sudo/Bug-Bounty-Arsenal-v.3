#!/usr/bin/env python3
"""
Reset Django migration state and recreate database schema
WARNING: This will drop ALL tables and recreate them fresh
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
print("DATABASE RESET - CLEARING ALL TABLES")
print("=" * 60)

# Get all tables
cursor.execute("""
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public'
    AND table_type = 'BASE TABLE'
    ORDER BY table_name;
""")
tables = cursor.fetchall()

print(f"\nFound {len(tables)} tables to drop:")
for (table,) in tables:
    print(f"  - {table}")

if len(tables) > 0:
    print("\nDropping tables...")
    for (table,) in tables:
        try:
            cursor.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE;')
            print(f"  ✓ Dropped {table}")
        except Exception as e:
            print(f"  ✗ Failed to drop {table}: {e}")

    connection.commit()
    print("\n✓ All tables dropped")
else:
    print("\n✓ No tables to drop - database already clean")

print("\n" + "=" * 60)
print("NEXT STEPS")
print("=" * 60)
print("1. Run migrations: python manage.py migrate")
print("2. Create superuser: python create_superuser.py")
print("3. Restart gunicorn: pkill gunicorn && /home/bugbount/app/start_gunicorn.sh")

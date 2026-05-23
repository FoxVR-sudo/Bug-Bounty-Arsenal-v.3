import os
import sys
import django

# Add project to path
sys.path.insert(0, '/home/bugbount/app')

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Setup Django
django.setup()

# Run migrations
from django.core.management import call_command  # noqa: E402

print("Running migrations...")
call_command('migrate')

print("\nCollecting static files...")
call_command('collectstatic', '--noinput')

print("\nDone!")

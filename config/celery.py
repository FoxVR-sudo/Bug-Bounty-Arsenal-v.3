"""
Celery configuration for BugBounty Arsenal.

This module configures the Celery application for asynchronous task execution,
particularly for running security scans in the background.
"""

import os
import sys
from pathlib import Path
from celery import Celery
from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Add project root to Python path for scanner imports
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Load .env file to get Redis configuration
load_dotenv(BASE_DIR / '.env')

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('bugbounty_arsenal')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Import scanner to register all detectors at startup
# This must happen AFTER app.config_from_object() to ensure Django settings are loaded
try:
    import scanner  # noqa: F401  (side effects) - triggers all detector imports in scanner.py
    from detectors.registry import ACTIVE_DETECTORS, PASSIVE_DETECTORS
    print(f"✓ Celery startup: Registered {len(ACTIVE_DETECTORS)} active and {len(PASSIVE_DETECTORS)} passive detectors")
except Exception as e:
    print(f"✗ Celery startup error loading detectors: {e}")


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task for testing Celery setup."""
    print(f'Request: {self.request!r}')

"""
Pytest configuration and fixtures for BugBounty Arsenal
"""
import pytest
import sys
from pathlib import Path

# Add project root to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from django.test import Client  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402
from rest_framework.test import APIClient  # noqa: E402
from subscriptions.models import Plan, Subscription  # noqa: E402
from scans.category_models import ScanCategory, DetectorConfig  # noqa: E402

User = get_user_model()


@pytest.fixture
def api_client():
    """DRF API client for testing authenticated endpoints"""
    return APIClient()


@pytest.fixture
def django_client():
    """Django test client"""
    return Client()


@pytest.fixture
def test_user(db):
    """Create a test user"""
    user = User.objects.create_user(
        email='test@example.com',
        password='testpass123',
        first_name='Test',
        middle_name='Middle',
        last_name='User',
        phone='+12345678901',
        is_verified=True,
    )
    return user


@pytest.fixture
def test_admin(db):
    """Create a test admin user"""
    admin = User.objects.create_superuser(
        email='admin@example.com',
        password='admin123',
        first_name='Admin',
        last_name='User',
    )
    return admin


@pytest.fixture
def authenticated_client(api_client, test_user):
    """API client with authenticated test user"""
    api_client.force_authenticate(user=test_user)
    return api_client


@pytest.fixture
def free_plan(db):
    """Create FREE plan"""
    plan, _ = Plan.objects.get_or_create(
        name='free',
        defaults={
            'display_name': 'Free',
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
            'features': ['Basic scanning', 'Email support']
        }
    )
    return plan


@pytest.fixture
def pro_plan(db):
    """Create PRO plan"""
    plan, _ = Plan.objects.get_or_create(
        name='pro',
        defaults={
            'display_name': 'Pro',
            'price': 20.00,
            'scans_per_day': 50,
            'scans_per_month': 1000,
            'concurrent_scans': 5,
            'storage_limit_mb': 5000,
            'retention_days': 30,
            'allow_dangerous_tools': False,
            'allow_teams': True,
            'max_team_members': 5,
            'allow_integrations': True,
            'max_integrations': 5,
            'features': ['Advanced scanning', 'Teams', 'Integrations', 'Priority support']
        }
    )
    return plan


@pytest.fixture
def enterprise_plan(db):
    """Create ENTERPRISE plan"""
    plan, _ = Plan.objects.get_or_create(
        name='enterprise',
        defaults={
            'display_name': 'Enterprise',
            'price': 100.00,
            'scans_per_day': -1,  # Unlimited
            'scans_per_month': -1,  # Unlimited
            'concurrent_scans': 10,
            'storage_limit_mb': -1,  # Unlimited
            'retention_days': 90,
            'allow_dangerous_tools': True,
            'allow_teams': True,
            'max_team_members': -1,  # Unlimited
            'allow_integrations': True,
            'max_integrations': -1,  # Unlimited
            'features': ['Unlimited scans', 'Custom tools', 'Dedicated support', '24/7 monitoring']
        }
    )
    return plan
    plan, _ = Plan.objects.get_or_create(
        name='ENTERPRISE',
        defaults={
            'price': 100.00,
            'daily_scans_limit': -1,  # Unlimited
            'monthly_scans_limit': -1,  # Unlimited
            'max_concurrent_scans': 20,
            'features': {
                'recon': True,
                'web_security': True,
                'api_security': True,
                'mobile': True,
                'vulnerability': True,
                'custom': True,
                'teams': True,
                'integrations': True,
                'priority_support': True
            }
        }
    )
    return plan


@pytest.fixture
def user_subscription(db, test_user, free_plan):
    """Create subscription for test user"""
    subscription, _ = Subscription.objects.get_or_create(
        user=test_user,
        defaults={
            'plan': free_plan,
            'status': 'active',
            'scans_used_today': 0,
            'scans_used_this_month': 0,
        }
    )
    return subscription


@pytest.fixture
def scan_categories(db):
    """Create all scan categories"""
    categories = []
    category_data = [
        {
            'name': 'recon',
            'display_name': 'Reconnaissance Scan',
            'description': 'Subdomain enumeration, tech stack detection',
            'icon': '🔍',
            'required_plan': 'free',
            'order': 1,
        },
        {
            'name': 'web',
            'display_name': 'Web Application Scan',
            'description': 'XSS, SQL Injection, CSRF, etc.',
            'icon': '🌐',
            'required_plan': 'free',
            'order': 2,
        },
        {
            'name': 'api',
            'display_name': 'API Security Scan',
            'description': 'GraphQL, JWT, OAuth testing',
            'icon': '🔌',
            'required_plan': 'pro',
            'order': 3,
        },
        {
            'name': 'vuln',
            'display_name': 'Vulnerability Scan',
            'description': 'CVE database scanning',
            'icon': '🛡️',
            'required_plan': 'pro',
            'order': 4,
        },
        {
            'name': 'mobile',
            'display_name': 'Mobile Security Scan',
            'description': 'Mobile app security testing',
            'icon': '📱',
            'required_plan': 'pro',
            'order': 5,
        },
        {
            'name': 'custom',
            'display_name': 'Custom Scan (All Tools)',
            'description': 'All detectors + dangerous tools',
            'icon': '⚡',
            'required_plan': 'enterprise',
            'order': 6,
        },
    ]

    for data in category_data:
        name = data.pop('name')
        category, _ = ScanCategory.objects.get_or_create(
            name=name,
            defaults={'name': name, **data},
        )
        categories.append(category)

    return categories


@pytest.fixture
def detector_configs(db, scan_categories):
    """Create detector configurations"""
    detectors = []

    # Find categories to attach to detectors
    web_category = next((c for c in scan_categories if c.name == 'web'), None)
    recon_category = next((c for c in scan_categories if c.name == 'recon'), None)

    xss_detector, _ = DetectorConfig.objects.get_or_create(
        name='xss_pattern_detector',
        defaults={
            'display_name': 'XSS Pattern Detection',
            'description': 'Detects Cross-Site Scripting vulnerabilities',
            'severity': 'high',
            'tags': ['xss', 'injection'],
            'is_dangerous': False,
            'requires_oob': False,
            'execution_order': 10,
            'timeout_seconds': 30,
            'max_concurrency': 10,
            'is_active': True,
        },
    )
    if web_category:
        xss_detector.categories.add(web_category)
    detectors.append(xss_detector)

    secret_detector, _ = DetectorConfig.objects.get_or_create(
        name='secret_detector',
        defaults={
            'display_name': 'Secret Detection',
            'description': 'Searches for leaked secrets in responses',
            'severity': 'medium',
            'tags': ['secrets', 'recon'],
            'is_dangerous': False,
            'requires_oob': False,
            'execution_order': 20,
            'timeout_seconds': 30,
            'max_concurrency': 10,
            'is_active': True,
        },
    )
    if recon_category:
        secret_detector.categories.add(recon_category)
    detectors.append(secret_detector)

    return detectors


@pytest.fixture
def mock_scan_response():
    """Mock HTTP response for scan testing"""
    class MockResponse:
        def __init__(self, status_code=200, text='', headers=None):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.content = text.encode()

        def json(self):
            import json
            return json.loads(self.text)

    return MockResponse


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    """Enable database access for all tests"""

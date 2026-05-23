"""
Tests for subscription system
"""
import pytest
from django.urls import reverse
from rest_framework import status


class TestSubscriptionAPI:
    """Test subscription endpoints"""

    @pytest.mark.api
    def test_list_plans(self, api_client, free_plan, pro_plan, enterprise_plan):
        """Test listing all available plans"""
        url = reverse('plans-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)
        assert len(response.data) == 3

        # Verify plan details
        plan_names = {p['name'] for p in response.data}
        assert 'free' in plan_names
        assert 'pro' in plan_names
        assert 'enterprise' in plan_names

    @pytest.mark.api
    def test_get_current_subscription(self, authenticated_client, user_subscription):
        """Test getting user's current subscription"""
        url = reverse('subscription-current')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['plan']['name'] == 'free'
        assert response.data['status'] == 'active'

    @pytest.mark.api
    def test_change_plan_requires_new_plan_id(self, authenticated_client):
        """Test validation error when new_plan_id is missing"""
        url = reverse('subscription-change-plan')
        response = authenticated_client.post(url, {}, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.api
    def test_change_plan_returns_503_when_stripe_not_configured(self, authenticated_client, pro_plan, settings):
        """When Stripe is not configured, endpoint should not 500."""
        settings.STRIPE_SECRET_KEY = ''
        url = reverse('subscription-change-plan')
        response = authenticated_client.post(url, {'new_plan_id': pro_plan.id}, format='json')
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    @pytest.mark.api
    def test_subscription_usage_tracking(self, authenticated_client, user_subscription):
        """Test that subscription tracks usage correctly"""
        url = reverse('subscription-current')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'scans_used_today' in response.data
        assert 'scans_used_this_month' in response.data
        assert 'daily_scan_limit' in response.data
        assert 'monthly_scan_limit' in response.data


class TestSubscriptionLimits:
    """Test subscription limit enforcement"""

    @pytest.mark.api
    def test_free_plan_limits(self, free_plan):
        """Verify FREE plan limits"""
        assert free_plan.scans_per_day == 3
        assert free_plan.scans_per_month == 30
        assert free_plan.concurrent_scans == 1
        assert free_plan.allow_teams is False
        assert free_plan.allow_integrations is False

    @pytest.mark.api
    def test_pro_plan_limits(self, pro_plan):
        """Verify PRO plan limits"""
        assert pro_plan.scans_per_day == 50
        assert pro_plan.scans_per_month == 1000
        assert pro_plan.concurrent_scans == 5
        assert pro_plan.allow_teams is True
        assert pro_plan.allow_integrations is True

    @pytest.mark.api
    def test_enterprise_plan_limits(self, enterprise_plan):
        """Verify ENTERPRISE plan limits"""
        assert enterprise_plan.scans_per_day == -1  # Unlimited
        assert enterprise_plan.scans_per_month == -1  # Unlimited
        assert enterprise_plan.concurrent_scans == 10
        assert enterprise_plan.allow_dangerous_tools is True

from rest_framework import serializers
from .models import Plan, Subscription


class PlanSerializer(serializers.ModelSerializer):
    """Serializer for Plan model"""
    daily_scan_limit = serializers.IntegerField(source='scans_per_day', read_only=True)
    monthly_scan_limit = serializers.IntegerField(source='scans_per_month', read_only=True)

    class Meta:
        model = Plan
        fields = ['id', 'name', 'display_name', 'price', 'description',
                  'daily_scan_limit', 'monthly_scan_limit', 'concurrent_scans',
                  'storage_limit_mb', 'retention_days',
                  'allow_dangerous_tools', 'allow_teams', 'max_team_members',
                  'allow_integrations', 'max_integrations',
                  'features', 'is_active', 'is_popular', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class SubscriptionSerializer(serializers.ModelSerializer):
    """Serializer for Subscription model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    plan_name = serializers.CharField(source='plan.display_name', read_only=True)

    class Meta:
        model = Subscription
        fields = ['id', 'user', 'user_email', 'plan', 'plan_name', 'status',
                  'stripe_customer_id', 'stripe_subscription_id',
                  'current_period_start', 'current_period_end', 'cancel_at_period_end',
                  'scans_used_today', 'last_scan_reset', 'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'scans_used_today', 'last_scan_reset',
                            'created_at', 'updated_at']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class SubscriptionUsageSerializer(serializers.ModelSerializer):
    """Serializer for subscription usage information"""
    plan_name = serializers.CharField(source='plan.display_name', read_only=True)
    daily_scan_limit = serializers.IntegerField(source='plan.scans_per_day', read_only=True)
    monthly_scan_limit = serializers.IntegerField(source='plan.scans_per_month', read_only=True)
    can_scan = serializers.SerializerMethodField()

    class Meta:
        model = Subscription
        fields = ['id', 'plan_name', 'daily_scan_limit', 'monthly_scan_limit', 'status',
                  'scans_used_today', 'scans_used_this_month', 'can_scan',
                  'current_period_end', 'cancel_at_period_end']
        read_only_fields = ['id', 'plan_name', 'daily_scan_limit', 'monthly_scan_limit', 'status',
                            'scans_used_today', 'scans_used_this_month', 'can_scan',
                            'current_period_end', 'cancel_at_period_end']

    def get_can_scan(self, obj):
        return obj.can_start_scan()

from rest_framework import serializers

from .integration_models import Integration


class IntegrationSerializer(serializers.ModelSerializer):
    enabled = serializers.BooleanField(source="is_active", required=False)
    team_name = serializers.CharField(source="team.name", read_only=True)

    class Meta:
        model = Integration
        fields = [
            "id",
            "team",
            "team_name",
            "integration_type",
            "name",
            "enabled",
            "config",
            "events",
            "status",
            "last_error",
            "last_error_at",
            "error_count",
            "total_triggers",
            "successful_triggers",
            "failed_triggers",
            "last_triggered_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "status",
            "last_error",
            "last_error_at",
            "error_count",
            "total_triggers",
            "successful_triggers",
            "failed_triggers",
            "last_triggered_at",
            "created_at",
            "updated_at",
        ]

    def validate(self, attrs):
        integration_type = attrs.get("integration_type") or getattr(self.instance, "integration_type", None)
        config = attrs.get("config") or getattr(self.instance, "config", {}) or {}
        events = attrs.get("events")

        if not integration_type:
            raise serializers.ValidationError({"integration_type": "This field is required."})

        # Normalize events to dict-of-bools to match frontend
        if events is None:
            events = getattr(self.instance, "events", None)
        if events is None:
            events = {}

        if isinstance(events, list):
            events = {e: True for e in events}
        if not isinstance(events, dict):
            raise serializers.ValidationError({"events": "Expected an object (event flags) or list of event names."})

        required_by_type = {
            "slack": ["webhook_url"],
            "discord": ["webhook_url"],
            "webhook": ["webhook_url"],
            "telegram": ["api_key", "channel"],
            "jira": ["api_key", "webhook_url"],
            "github": ["api_key", "webhook_url"],
            "gitlab": ["api_key", "webhook_url"],
            "email": ["channel"],
        }
        for field in required_by_type.get(integration_type, []):
            if not config.get(field):
                raise serializers.ValidationError({"config": {field: "This field is required."}})

        attrs["events"] = events
        attrs["config"] = config
        return attrs

    def create(self, validated_data):
        request = self.context.get("request")
        user = getattr(request, "user", None)

        if not validated_data.get("name"):
            integration_type = validated_data.get("integration_type")
            validated_data["name"] = dict(Integration.INTEGRATION_TYPES).get(integration_type, integration_type)

        enabled = validated_data.pop("is_active", True)
        integration = Integration.objects.create(
            user=user,
            is_active=enabled,
            **validated_data,
        )
        return integration

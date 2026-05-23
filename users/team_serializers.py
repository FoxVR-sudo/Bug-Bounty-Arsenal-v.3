from django.contrib.auth import get_user_model
from rest_framework import serializers

from .team_models import Team, TeamMember, TeamInvitation

User = get_user_model()


class TeamSerializer(serializers.ModelSerializer):
    owner_email = serializers.EmailField(source="owner.email", read_only=True)
    member_count = serializers.IntegerField(read_only=True)
    can_add_members = serializers.BooleanField(read_only=True)

    class Meta:
        model = Team
        fields = [
            "id",
            "name",
            "description",
            "owner",
            "owner_email",
            "max_members",
            "is_active",
            "invite_code",
            "member_count",
            "can_add_members",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "owner",
            "owner_email",
            "invite_code",
            "member_count",
            "can_add_members",
            "created_at",
            "updated_at",
        ]


class TeamMemberSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source="user.email", read_only=True)
    user_first_name = serializers.CharField(source="user.first_name", read_only=True)
    user_last_name = serializers.CharField(source="user.last_name", read_only=True)

    class Meta:
        model = TeamMember
        fields = [
            "id",
            "team",
            "user",
            "user_email",
            "user_first_name",
            "user_last_name",
            "role",
            "can_create_scans",
            "can_view_all_scans",
            "can_delete_scans",
            "can_manage_members",
            "use_custom_permissions",
            "is_active",
            "invited_by",
            "joined_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "team",
            "user",
            "user_email",
            "user_first_name",
            "user_last_name",
            "can_create_scans",
            "can_view_all_scans",
            "can_delete_scans",
            "can_manage_members",
            "use_custom_permissions",
            "invited_by",
            "joined_at",
            "updated_at",
        ]


class TeamInvitationSerializer(serializers.ModelSerializer):
    invited_by_email = serializers.EmailField(source="invited_by.email", read_only=True)

    class Meta:
        model = TeamInvitation
        fields = [
            "id",
            "team",
            "email",
            "invited_by",
            "invited_by_email",
            "role",
            "status",
            "expires_at",
            "created_at",
            "updated_at",
            "accepted_at",
        ]
        read_only_fields = [
            "id",
            "team",
            "invited_by",
            "invited_by_email",
            "status",
            "expires_at",
            "created_at",
            "updated_at",
            "accepted_at",
        ]

import pytest
from rest_framework import status
from django.contrib.auth import get_user_model

from subscriptions.models import Subscription
from users.team_models import Team, TeamMember

User = get_user_model()


@pytest.mark.django_db
class TestTeamMemberPermissionsAPI:
    @pytest.mark.api
    def test_owner_can_set_custom_permissions(self, authenticated_client, test_user, pro_plan):
        # Ensure owner has a plan that allows teams.
        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                "plan": pro_plan,
                "status": "active",
                "scans_used_today": 0,
                "scans_used_this_month": 0,
            },
        )

        team = Team.objects.create(owner=test_user, name="Acme", max_members=5)

        member_user = User.objects.create_user(
            email="member1@example.com",
            password="pass12345",
            first_name="M",
            last_name="One",
            is_verified=True,
        )
        member = TeamMember.objects.create(team=team, user=member_user, role="viewer", invited_by=test_user)

        url = f"/api/teams/{team.id}/members/{member.id}/permissions/"
        payload = {
            "use_custom_permissions": True,
            "can_create_scans": True,
            "can_delete_scans": True,
        }
        res = authenticated_client.patch(url, payload, format="json")

        assert res.status_code == status.HTTP_200_OK
        assert res.data["use_custom_permissions"] is True

        member.refresh_from_db()
        assert member.use_custom_permissions is True
        assert member.can_create_scans is True
        assert member.can_delete_scans is True

    @pytest.mark.api
    def test_cannot_override_permissions_without_custom_flag(self, authenticated_client, test_user, pro_plan):
        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                "plan": pro_plan,
                "status": "active",
                "scans_used_today": 0,
                "scans_used_this_month": 0,
            },
        )

        team = Team.objects.create(owner=test_user, name="Acme2", max_members=5)

        member_user = User.objects.create_user(
            email="member2@example.com",
            password="pass12345",
            first_name="M",
            last_name="Two",
            is_verified=True,
        )
        member = TeamMember.objects.create(team=team, user=member_user, role="member", invited_by=test_user)

        url = f"/api/teams/{team.id}/members/{member.id}/permissions/"
        payload = {
            "use_custom_permissions": False,
            "can_delete_scans": True,
        }
        res = authenticated_client.patch(url, payload, format="json")

        assert res.status_code == status.HTTP_400_BAD_REQUEST
        member.refresh_from_db()
        assert member.can_delete_scans is False

    @pytest.mark.api
    def test_member_without_manage_members_cannot_update_permissions(self, api_client, test_user, pro_plan):
        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                "plan": pro_plan,
                "status": "active",
                "scans_used_today": 0,
                "scans_used_this_month": 0,
            },
        )

        team = Team.objects.create(owner=test_user, name="Acme3", max_members=5)

        acting_user = User.objects.create_user(
            email="viewer@example.com",
            password="pass12345",
            first_name="V",
            last_name="User",
            is_verified=True,
        )
        TeamMember.objects.create(team=team, user=acting_user, role="viewer", invited_by=test_user)

        target_user = User.objects.create_user(
            email="target@example.com",
            password="pass12345",
            first_name="T",
            last_name="User",
            is_verified=True,
        )
        target_member = TeamMember.objects.create(team=team, user=target_user, role="member", invited_by=test_user)

        api_client.force_authenticate(user=acting_user)

        url = f"/api/teams/{team.id}/members/{target_member.id}/permissions/"
        res = api_client.patch(url, {"use_custom_permissions": True, "can_delete_scans": True}, format="json")
        assert res.status_code == status.HTTP_403_FORBIDDEN

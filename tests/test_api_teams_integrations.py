"""API integration tests for Teams and Integrations endpoints.

These cover basic CRUD and plan gating (Free vs Pro).
"""

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status

from subscriptions.models import Subscription
from users.integration_models import Integration
from users.team_models import Team, TeamMember


User = get_user_model()


@pytest.mark.api
class TestTeamsAPI:
    def test_teams_create_forbidden_on_free(self, authenticated_client, test_user, free_plan):
        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                'plan': free_plan,
                'status': 'active',
            },
        )

        url = reverse('api:team-list')
        response = authenticated_client.post(
            url,
            {
                'name': 'My Team',
                'description': 'Test team',
            },
            format='json',
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert 'error' in response.data

    def test_teams_crud_happy_path_on_pro(self, authenticated_client, test_user, pro_plan):
        # Upgrade user to Pro.
        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                'plan': pro_plan,
                'status': 'active',
            },
        )

        create_url = reverse('api:team-list')
        created = authenticated_client.post(
            create_url,
            {
                'name': 'Red Team',
                'description': 'Security team',
            },
            format='json',
        )
        assert created.status_code == status.HTTP_201_CREATED
        team_id = created.data['id']

        # List
        listed = authenticated_client.get(create_url)
        assert listed.status_code == status.HTTP_200_OK
        assert any(t['id'] == team_id for t in listed.data['results'])

        # Retrieve
        detail_url = reverse('api:team-detail', kwargs={'pk': team_id})
        detail = authenticated_client.get(detail_url)
        assert detail.status_code == status.HTTP_200_OK
        assert detail.data['id'] == team_id

        # Members action should include owner
        members_url = reverse('api:team-members', kwargs={'pk': team_id})
        members = authenticated_client.get(members_url)
        assert members.status_code == status.HTTP_200_OK
        assert any(m.get('user') == test_user.id for m in members.data)

        # Invite
        invite_url = reverse('api:team-invite', kwargs={'pk': team_id})
        invited = authenticated_client.post(
            invite_url,
            {'email': 'invitee@example.com', 'role': 'member'},
            format='json',
        )
        assert invited.status_code == status.HTTP_201_CREATED
        assert invited.data['email'] == 'invitee@example.com'

        # Invitations list
        invitations_url = reverse('api:team-invitations', kwargs={'pk': team_id})
        invitations = authenticated_client.get(invitations_url)
        assert invitations.status_code == status.HTTP_200_OK
        assert any(inv.get('email') == 'invitee@example.com' for inv in invitations.data)

        # Update
        patched = authenticated_client.patch(
            detail_url,
            {'description': 'Updated desc'},
            format='json',
        )
        assert patched.status_code == status.HTTP_200_OK
        assert patched.data['description'] == 'Updated desc'

        # Delete
        deleted = authenticated_client.delete(detail_url)
        assert deleted.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.api
class TestIntegrationsAPI:
    def test_integrations_create_forbidden_on_free(self, authenticated_client, test_user, free_plan):
        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                'plan': free_plan,
                'status': 'active',
            },
        )

        url = reverse('api:integration-list')
        response = authenticated_client.post(
            url,
            {
                'integration_type': 'webhook',
                'name': 'My Webhook',
                'enabled': True,
                'config': {'webhook_url': 'https://example.com/webhook'},
                'events': {'scan_completed': True},
            },
            format='json',
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert 'error' in response.data

    def test_integrations_crud_happy_path_on_pro(self, authenticated_client, test_user, pro_plan):
        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                'plan': pro_plan,
                'status': 'active',
            },
        )

        create_url = reverse('api:integration-list')
        created = authenticated_client.post(
            create_url,
            {
                'integration_type': 'webhook',
                'name': 'CI Webhook',
                'enabled': True,
                'config': {'webhook_url': 'https://example.com/webhook'},
                'events': {'scan_completed': True, 'scan_failed': True},
            },
            format='json',
        )
        assert created.status_code == status.HTTP_201_CREATED
        integration_id = created.data['id']

        # List
        listed = authenticated_client.get(create_url)
        assert listed.status_code == status.HTTP_200_OK
        assert any(i['id'] == integration_id for i in listed.data['results'])

        # Retrieve
        detail_url = reverse('api:integration-detail', kwargs={'pk': integration_id})
        detail = authenticated_client.get(detail_url)
        assert detail.status_code == status.HTTP_200_OK
        assert detail.data['id'] == integration_id

        # Update (toggle enabled)
        patched = authenticated_client.patch(
            detail_url,
            {'enabled': False},
            format='json',
        )
        assert patched.status_code == status.HTTP_200_OK
        assert patched.data['enabled'] is False

        # Delete
        deleted = authenticated_client.delete(detail_url)
        assert deleted.status_code == status.HTTP_204_NO_CONTENT

    def test_team_integrations_visible_but_not_editable_for_non_admin(self, authenticated_client, test_user, pro_plan):
        # Member user is Pro (plan gating is mainly for create, but keep it consistent).
        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                'plan': pro_plan,
                'status': 'active',
            },
        )

        owner = User.objects.create_user(
            email='owner@example.com',
            password='ownerpass123',
            first_name='Owner',
            last_name='User',
            is_verified=True,
        )
        Subscription.objects.update_or_create(
            user=owner,
            defaults={
                'plan': pro_plan,
                'status': 'active',
            },
        )

        team = Team.objects.create(name='Blue Team', description='Team', owner=owner, max_members=5, is_active=True)
        TeamMember.objects.get_or_create(team=team, user=owner, defaults={'role': 'admin', 'invited_by': owner})
        TeamMember.objects.create(team=team, user=test_user, role='member', invited_by=owner, is_active=True)

        integration = Integration.objects.create(
            user=owner,
            team=team,
            integration_type='webhook',
            name='Team Webhook',
            is_active=True,
            status='active',
            config={'webhook_url': 'https://example.com/webhook'},
            events={'scan_completed': True},
        )

        list_url = reverse('api:integration-list')
        listed = authenticated_client.get(list_url)
        assert listed.status_code == status.HTTP_200_OK
        assert any(i['id'] == integration.id for i in listed.data['results'])

        detail_url = reverse('api:integration-detail', kwargs={'pk': integration.id})
        patched = authenticated_client.patch(detail_url, {'enabled': False}, format='json')
        assert patched.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.api
class TestIntegrationDeliveryHardening:
    def test_http_delivery_retries_then_succeeds(self, test_user, pro_plan, monkeypatch):
        import requests

        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                'plan': pro_plan,
                'status': 'active',
            },
        )

        integration = Integration.objects.create(
            user=test_user,
            integration_type='webhook',
            name='Retry Webhook',
            is_active=True,
            status='active',
            config={'webhook_url': 'https://example.com/webhook', 'max_retries': 2},
            events={'scan_completed': True},
        )

        calls = {'n': 0}

        def fake_post(*args, **kwargs):
            calls['n'] += 1
            if calls['n'] < 3:
                raise requests.RequestException('temporary network error')

            class Resp:
                status_code = 200

            return Resp()

        monkeypatch.setattr(requests, 'post', fake_post)

        ok, _message = integration.trigger(
            'scan_completed',
            {
                'target': 'https://example.com',
                'scan_type': 'web_security',
                'status': 'completed',
                'vulnerabilities_found': 0,
            },
        )
        assert ok is True
        assert calls['n'] == 3

        integration.refresh_from_db()
        assert integration.error_count == 0

    def test_webhook_signature_headers_added_when_secret_present(self, test_user, pro_plan, monkeypatch):
        import requests

        Subscription.objects.update_or_create(
            user=test_user,
            defaults={
                'plan': pro_plan,
                'status': 'active',
            },
        )

        integration = Integration.objects.create(
            user=test_user,
            integration_type='webhook',
            name='Signed Webhook',
            is_active=True,
            status='active',
            # For backwards compatibility, api_key also acts as signing secret for webhooks.
            config={'webhook_url': 'https://example.com/webhook', 'api_key': 'supersecret'},
            events={'scan_completed': True},
        )

        captured = {}

        def fake_post(url, *args, **kwargs):
            captured['url'] = url
            captured['kwargs'] = kwargs

            class Resp:
                status_code = 200

            return Resp()

        monkeypatch.setattr(requests, 'post', fake_post)

        ok, _message = integration.trigger(
            'scan_completed',
            {
                'target': 'https://example.com',
                'scan_type': 'web_security',
                'status': 'completed',
                'vulnerabilities_found': 0,
            },
        )
        assert ok is True

        headers = captured['kwargs'].get('headers') or {}
        assert headers.get('X-BBA-Signature')
        assert headers.get('X-BBA-Timestamp')
        assert headers.get('X-BBA-Event') == 'scan_completed'

        # When signing is enabled we send a deterministic JSON body.
        assert isinstance(captured['kwargs'].get('data'), str)
        assert captured['kwargs'].get('json') is None

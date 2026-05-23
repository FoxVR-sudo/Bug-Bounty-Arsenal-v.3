from django.db.models import Q
from django.conf import settings
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .integration_models import Integration
from .integration_serializers import IntegrationSerializer
from .team_models import Team, TeamMember


def _get_active_subscription(user):
    try:
        sub = getattr(user, "subscription", None)
        if sub and sub.status == "active":
            return sub
    except Exception:
        return None
    return None


class IntegrationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = IntegrationSerializer

    def get_queryset(self):
        user = self.request.user
        team_ids = list(
            TeamMember.objects.filter(user=user, is_active=True)
            .values_list("team_id", flat=True)
            .distinct()
        )
        q = Q(user=user)
        if team_ids:
            q |= Q(team_id__in=team_ids)
        return Integration.objects.filter(q).distinct().order_by("-created_at")

    def _can_manage_integration(self, integration: Integration, user) -> bool:
        if integration.user_id == user.id:
            return True
        if not integration.team_id:
            return False
        if getattr(integration.team, "owner_id", None) == user.id:
            return True
        return TeamMember.objects.filter(
            team_id=integration.team_id,
            user=user,
            is_active=True,
            role="admin",
        ).exists()

    def update(self, request, *args, **kwargs):
        integration = self.get_object()
        if not self._can_manage_integration(integration, request.user):
            return Response({"error": "You do not have permission to modify this integration"},
                            status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        integration = self.get_object()
        if not self._can_manage_integration(integration, request.user):
            return Response({"error": "You do not have permission to modify this integration"},
                            status=status.HTTP_403_FORBIDDEN)
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        integration = self.get_object()
        if not self._can_manage_integration(integration, request.user):
            return Response({"error": "You do not have permission to delete this integration"},
                            status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        # Skip subscription gate when paid plans are disabled
        if getattr(settings, 'PAID_PLANS_ENABLED', True):
            subscription = _get_active_subscription(request.user)
            if not subscription or not subscription.plan.allow_integrations:
                return Response(
                    {"error": "Integrations feature available in Pro plan"},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Plan limit check
            max_integrations = subscription.plan.max_integrations
            if max_integrations != -1:
                team_id = request.data.get("team")
                if team_id:
                    # Allow creating a team-scoped integration only for team owner/admin.
                    is_team_admin = TeamMember.objects.filter(
                        team_id=team_id,
                        user=request.user,
                        is_active=True,
                        role="admin",
                    ).exists()
                    is_team_owner = Team.objects.filter(
                        id=team_id, owner=request.user, is_active=True
                    ).exists()
                    if not (is_team_admin or is_team_owner):
                        return Response(
                            {
                                'error': 'You do not have permission to create integrations for this team'
                            },
                            status=status.HTTP_403_FORBIDDEN,
                        )

                    active_count = Integration.objects.filter(team_id=team_id, is_active=True).count()
                else:
                    active_count = Integration.objects.filter(user=request.user, is_active=True).count()
                if active_count >= max_integrations:
                    return Response(
                        {"error": f"Maximum active integrations reached ({max_integrations})"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        return super().create(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="test")
    def test(self, request, pk=None):
        integration = self.get_object()
        if not self._can_manage_integration(integration, request.user):
            return Response({"error": "You do not have permission to test this integration"},
                            status=status.HTTP_403_FORBIDDEN)
        ok, message = integration.test_connection()
        status_code = status.HTTP_200_OK if ok else status.HTTP_400_BAD_REQUEST
        return Response({"success": bool(ok), "message": message}, status=status_code)

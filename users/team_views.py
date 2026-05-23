from django.db.models import Q
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


from .team_models import Team, TeamMember, TeamInvitation
from .team_serializers import TeamSerializer, TeamMemberSerializer, TeamInvitationSerializer


def _get_active_subscription(user):
    try:
        sub = getattr(user, "subscription", None)
        if sub and sub.status == "active":
            return sub
    except Exception:
        return None
    return None


class TeamViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = TeamSerializer

    def get_queryset(self):
        user = self.request.user
        return (
            Team.objects.filter(Q(owner=user) | Q(members__user=user))
            .distinct()
            .order_by("-created_at")
        )

    def perform_create(self, serializer):
        user = self.request.user
        subscription = _get_active_subscription(user)
        if not subscription or not subscription.plan.allow_teams:
            raise PermissionError("Teams feature available in Pro plan")

        max_members = subscription.plan.max_team_members
        team = serializer.save(owner=user, max_members=max_members)

        # Ensure owner is also a team admin member
        TeamMember.objects.get_or_create(
            team=team,
            user=user,
            defaults={"role": "admin", "invited_by": user},
        )

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except PermissionError as e:
            return Response({"error": str(e)}, status=status.HTTP_403_FORBIDDEN)

    def _get_membership(self, team: Team, user):
        if team.owner_id == user.id:
            return None
        return TeamMember.objects.filter(team=team, user=user, is_active=True).first()

    def _require_team_access(self, team: Team, user):
        if team.owner_id == user.id:
            return None
        membership = self._get_membership(team, user)
        if not membership:
            return Response({"error": "You do not have access to this team"}, status=status.HTTP_403_FORBIDDEN)
        return membership

    @action(detail=True, methods=["get"], url_path="members")
    def members(self, request, pk=None):
        team = self.get_object()
        denial = self._require_team_access(team, request.user)
        if isinstance(denial, Response):
            return denial

        members = TeamMember.objects.filter(team=team, is_active=True).select_related("user")
        return Response(TeamMemberSerializer(members, many=True).data)

    @action(detail=True, methods=["get"], url_path="invitations")
    def invitations(self, request, pk=None):
        team = self.get_object()
        denial = self._require_team_access(team, request.user)
        if isinstance(denial, Response):
            return denial

        invitations = TeamInvitation.objects.filter(team=team).order_by("-created_at")
        return Response(TeamInvitationSerializer(invitations, many=True).data)

    @action(detail=True, methods=["post"], url_path="invite")
    def invite(self, request, pk=None):
        team = self.get_object()
        membership = self._get_membership(team, request.user)
        if team.owner_id != request.user.id and not (membership and membership.can_manage_members):
            return Response({"error": "You do not have permission to invite members"}, status=status.HTTP_403_FORBIDDEN)

        # Team limit check
        if not team.can_add_members:
            return Response({"error": "Team has reached maximum members limit"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = TeamInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        invitation = TeamInvitation.objects.create(
            team=team,
            email=serializer.validated_data["email"],
            role=serializer.validated_data.get("role", "member"),
            invited_by=request.user,
        )
        return Response(TeamInvitationSerializer(invitation).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["delete"], url_path=r"members/(?P<member_id>\d+)")
    def remove_member(self, request, pk=None, member_id=None):
        team = self.get_object()
        membership = self._get_membership(team, request.user)
        if team.owner_id != request.user.id and not (membership and membership.can_manage_members):
            return Response({"error": "You do not have permission to remove members"}, status=status.HTTP_403_FORBIDDEN)

        member = TeamMember.objects.filter(team=team, id=member_id).first()
        if not member:
            return Response({"error": "Member not found"}, status=status.HTTP_404_NOT_FOUND)

        if member.user_id == team.owner_id:
            return Response({"error": "Cannot remove team owner"}, status=status.HTTP_400_BAD_REQUEST)

        member.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["patch"], url_path=r"members/(?P<member_id>\d+)/permissions")
    def update_member_permissions(self, request, pk=None, member_id=None):
        team = self.get_object()
        membership = self._get_membership(team, request.user)
        if team.owner_id != request.user.id and not (membership and membership.can_manage_members):
            return Response({"error": "You do not have permission to manage member permissions"},
                            status=status.HTTP_403_FORBIDDEN)

        member = TeamMember.objects.filter(team=team, id=member_id).select_related("user").first()
        if not member:
            return Response({"error": "Member not found"}, status=status.HTTP_404_NOT_FOUND)

        if member.user_id == team.owner_id:
            return Response({"error": "Cannot modify team owner permissions"}, status=status.HTTP_400_BAD_REQUEST)

        data = request.data if isinstance(request.data, dict) else {}

        allowed_roles = {r[0] for r in TeamMember.ROLES}
        if "role" in data:
            role = data.get("role")
            if role not in allowed_roles:
                return Response({"error": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)
            member.role = role

        target_use_custom = member.use_custom_permissions
        if "use_custom_permissions" in data:
            target_use_custom = bool(data.get("use_custom_permissions"))
            member.use_custom_permissions = target_use_custom

        perm_fields = {
            "can_create_scans",
            "can_view_all_scans",
            "can_delete_scans",
            "can_manage_members",
        }
        provided_perm_fields = perm_fields.intersection(data.keys())
        if provided_perm_fields and not target_use_custom:
            return Response(
                {"error": "Permission overrides require use_custom_permissions=true"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        for field in provided_perm_fields:
            member.__dict__[field] = bool(data.get(field))

        member.save()
        return Response(TeamMemberSerializer(member).data, status=status.HTTP_200_OK)

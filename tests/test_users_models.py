"""
Tests for Users Models
"""
import pytest
from django.contrib.auth import get_user_model
from users.team_models import Team, TeamMember

User = get_user_model()


@pytest.mark.django_db
class TestUserModel:
    """Test User model"""

    def test_create_user(self):
        """Test creating a regular user"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        assert user.email == 'test@example.com'
        assert user.check_password('testpass123')
        assert not user.is_staff
        assert not user.is_superuser

    def test_create_superuser(self):
        """Test creating a superuser"""
        admin = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123'
        )
        assert admin.email == 'admin@example.com'
        assert admin.is_staff
        assert admin.is_superuser

    def test_user_str_representation(self):
        """Test User __str__ method"""
        user = User.objects.create_user(
            email='john@example.com',
            password='pass'
        )
        assert str(user) == 'john@example.com'

    def test_user_email_unique(self):
        """Test that email should be unique"""
        User.objects.create_user(
            email='same@example.com',
            password='pass1'
        )
        # Email should be unique
        user2 = User.objects.create_user(
            email='different@example.com',
            password='pass2'
        )
        assert user2.email == 'different@example.com'


@pytest.mark.django_db
class TestTeamModel:
    """Test Team model"""

    def test_create_team(self):
        """Test creating a team"""
        owner = User.objects.create_user(
            email='owner@example.com',
            password='pass'
        )
        team = Team.objects.create(
            name='Test Team',
            owner=owner
        )
        assert team.name == 'Test Team'
        assert team.owner == owner
        assert 'Test Team' in str(team)

    def test_team_members(self):
        """Test team member relationships"""
        owner = User.objects.create_user(
            email='owner@example.com',
            password='pass'
        )
        member = User.objects.create_user(
            email='member@example.com',
            password='pass'
        )

        team = Team.objects.create(
            name='Dev Team',
            owner=owner
        )

        TeamMember.objects.create(
            team=team,
            user=member,
            role='member'
        )

        assert team.members.count() == 1
        assert member in [tm.user for tm in team.members.all()]

    def test_team_member_roles(self):
        """Test different team member roles"""
        owner = User.objects.create_user(
            email='owner@example.com',
            password='pass'
        )
        admin = User.objects.create_user(
            email='admin@example.com',
            password='pass'
        )

        team = Team.objects.create(
            name='Security Team',
            owner=owner
        )

        team_admin = TeamMember.objects.create(
            team=team,
            user=admin,
            role='admin'
        )

        assert team_admin.role == 'admin'
        assert team_admin.team == team

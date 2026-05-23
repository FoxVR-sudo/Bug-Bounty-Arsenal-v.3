"""
Team collaboration models for Pro and Enterprise plans
"""
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError


class Team(models.Model):
    """
    Team for collaborative work (Pro & Enterprise plans)
    """

    name = models.CharField(max_length=255, help_text='Team name')
    description = models.TextField(blank=True)

    # Owner (creator of the team)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='owned_teams'
    )

    # Team limits
    max_members = models.IntegerField(default=10, help_text='Maximum team members (default: 10)')

    # Settings
    is_active = models.BooleanField(default=True)
    invite_code = models.CharField(max_length=32, unique=True, blank=True, help_text='Unique invite code')

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'teams'
        ordering = ['-created_at']
        unique_together = [['owner', 'name']]

    def __str__(self):
        return f"{self.name} (Owner: {self.owner.email})"

    @property
    def member_count(self):
        """Current number of team members"""
        return self.members.filter(is_active=True).count()

    @property
    def can_add_members(self):
        """Check if team can add more members"""
        if self.max_members == -1:
            return True
        return self.member_count < self.max_members

    def clean(self):
        """Validate team can be created"""
        # Check owner's subscription plan
        if hasattr(self.owner, 'subscription'):
            plan = self.owner.subscription.plan
            plan_name = getattr(plan, 'name', plan)
            if plan_name not in ['pro', 'enterprise']:
                raise ValidationError('Teams are only available for Pro and Enterprise plans')

    def save(self, *args, **kwargs):
        # Generate invite code if not set
        if not self.invite_code:
            import secrets
            self.invite_code = secrets.token_urlsafe(16)
        super().save(*args, **kwargs)


class TeamMember(models.Model):
    """
    Team membership with roles
    """

    ROLES = [
        ('admin', 'Admin'),
        ('member', 'Member'),
        ('viewer', 'Viewer'),
    ]

    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='members')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='team_memberships')

    # Role and permissions
    role = models.CharField(max_length=20, choices=ROLES, default='member')

    # Permissions
    can_create_scans = models.BooleanField(default=True)
    can_view_all_scans = models.BooleanField(default=True)
    can_delete_scans = models.BooleanField(default=False)
    can_manage_members = models.BooleanField(default=False)

    # If enabled, do not auto-derive permissions from role.
    use_custom_permissions = models.BooleanField(default=False)

    # Status
    is_active = models.BooleanField(default=True)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='team_invitations_sent'
    )

    # Timestamps
    joined_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'team_members'
        ordering = ['-joined_at']
        unique_together = [['team', 'user']]

    def __str__(self):
        return f"{self.user.email} - {self.team.name} ({self.role})"

    def clean(self):
        """Validate team membership"""
        if self.team.max_members != -1 and self.team.member_count >= self.team.max_members and not self.pk:
            raise ValidationError(f'Team has reached maximum members limit ({self.team.max_members})')

    def save(self, *args, **kwargs):
        # Set permissions based on role unless custom overrides are enabled.
        if not self.use_custom_permissions:
            if self.role == 'admin':
                self.can_create_scans = True
                self.can_view_all_scans = True
                self.can_delete_scans = True
                self.can_manage_members = True
            elif self.role == 'member':
                self.can_create_scans = True
                self.can_view_all_scans = True
                self.can_delete_scans = False
                self.can_manage_members = False
            elif self.role == 'viewer':
                self.can_create_scans = False
                self.can_view_all_scans = True
                self.can_delete_scans = False
                self.can_manage_members = False

        super().save(*args, **kwargs)


class TeamInvitation(models.Model):
    """
    Pending team invitations
    """

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('declined', 'Declined'),
        ('expired', 'Expired'),
    ]

    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='invitations')
    email = models.EmailField(help_text='Email of invited user')
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='sent_invitations'
    )

    role = models.CharField(max_length=20, choices=TeamMember.ROLES, default='member')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    token = models.CharField(max_length=64, unique=True, help_text='Invitation token')
    expires_at = models.DateTimeField(help_text='Invitation expiry date')

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    accepted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'team_invitations'
        ordering = ['-created_at']

    def __str__(self):
        return f"Invitation to {self.email} for {self.team.name}"

    @property
    def is_expired(self):
        """Check if invitation has expired"""
        from django.utils import timezone
        return timezone.now() > self.expires_at

    def save(self, *args, **kwargs):
        # Generate token if not set
        if not self.token:
            import secrets
            self.token = secrets.token_urlsafe(32)

        # Set expiry date if not set (7 days from now)
        if not self.expires_at:
            from django.utils import timezone
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(days=7)

        super().save(*args, **kwargs)

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
import uuid


class UserManager(BaseUserManager):
    """Custom user manager"""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_admin', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom User model with email as username"""

    username = None  # Remove username field
    email = models.EmailField(unique=True)

    # Personal information (required for all plans)
    first_name = models.CharField(max_length=100, blank=True)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    full_name = models.CharField(max_length=255, blank=True)  # Auto-generated from first+middle+last
    address = models.TextField(blank=True, help_text='Full address')

    # Phone verification
    phone = models.CharField(max_length=20, blank=True, help_text='International format: +359XXXXXXXXX')
    phone_verified = models.BooleanField(default=False)
    phone_verification_code = models.CharField(max_length=200, blank=True, null=True)
    phone_verification_expires = models.DateTimeField(null=True, blank=True)

    # Company information (Enterprise plan)
    company_name = models.CharField(max_length=255, blank=True, help_text='Company/Organization name')
    company_registration_number = models.CharField(max_length=100, blank=True, help_text='Registration/VAT number')
    company_address = models.TextField(blank=True, help_text='Company address')
    company_country = models.CharField(max_length=2, blank=True, help_text='ISO country code')
    company_verified = models.BooleanField(default=False)
    company_verification_date = models.DateTimeField(null=True, blank=True)

    # Account status
    is_admin = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=100, blank=True, null=True)

    # Stripe integration
    stripe_customer_id = models.CharField(max_length=100, blank=True, null=True, help_text='Stripe customer ID')

    # Per-user API rate limits (requests/hour). None = use global default from settings.
    scan_start_hourly_limit = models.PositiveIntegerField(
        null=True, blank=True,
        help_text='Max scan starts per hour. Null = global default.',
    )
    scan_stop_hourly_limit = models.PositiveIntegerField(
        null=True, blank=True,
        help_text='Max scan stops per hour. Null = global default.',
    )
    export_hourly_limit = models.PositiveIntegerField(
        null=True, blank=True,
        help_text='Max exports per hour. Null = global default.',
    )

    # Two-factor authentication (TOTP + backup codes)
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=32, blank=True, null=True)
    two_factor_confirmed_at = models.DateTimeField(null=True, blank=True)
    two_factor_backup_codes = models.JSONField(default=list, blank=True)

    # Registration origin (captured when the account becomes a real user)
    registration_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text='IP address used at registration time',
    )
    registration_city = models.CharField(max_length=100, blank=True)
    registration_country = models.CharField(max_length=2, blank=True, help_text='ISO country code')
    registration_latitude = models.FloatField(null=True, blank=True)
    registration_longitude = models.FloatField(null=True, blank=True)
    registration_is_anonymous = models.BooleanField(null=True, blank=True)
    registration_is_proxy = models.BooleanField(null=True, blank=True)
    registration_is_vpn = models.BooleanField(null=True, blank=True)
    registration_is_tor = models.BooleanField(null=True, blank=True)
    registration_is_hosting = models.BooleanField(null=True, blank=True)

    # Last seen location (auto-detected from IP on each login)
    last_seen_ip = models.GenericIPAddressField(null=True, blank=True, help_text='Most recent client IP address')
    last_seen_city = models.CharField(max_length=100, blank=True)
    last_seen_country = models.CharField(max_length=2, blank=True, help_text='ISO country code')
    last_seen_latitude = models.FloatField(null=True, blank=True)
    last_seen_longitude = models.FloatField(null=True, blank=True)
    last_seen_is_anonymous = models.BooleanField(null=True, blank=True)
    last_seen_is_proxy = models.BooleanField(null=True, blank=True)
    last_seen_is_vpn = models.BooleanField(null=True, blank=True)
    last_seen_is_tor = models.BooleanField(null=True, blank=True)
    last_seen_is_hosting = models.BooleanField(null=True, blank=True)

    # Timestamps
    last_login = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'users'
        ordering = ['-created_at']

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        """Auto-generate full_name from first, middle, last names"""
        if self.first_name or self.middle_name or self.last_name:
            parts = [self.first_name, self.middle_name, self.last_name]
            self.full_name = ' '.join(filter(None, parts))
        super().save(*args, **kwargs)


class LegalAcceptance(models.Model):
    """Stores an auditable record of legal document acceptance (e.g. at signup)."""

    EVENT_SIGNUP = 'signup'
    EVENT_CHOICES = (
        (EVENT_SIGNUP, 'Signup'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='legal_acceptances')
    event = models.CharField(max_length=32, choices=EVENT_CHOICES, default=EVENT_SIGNUP, db_index=True)

    documents = models.JSONField(
        default=dict,
        blank=True,
        help_text='Mapping of document name to version, e.g. {"terms":"2026-01-23"}',
    )
    accepted = models.BooleanField(default=True)
    accepted_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    meta = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = 'legal_acceptances'
        ordering = ['-accepted_at']
        indexes = [
            models.Index(fields=['user', 'event', 'accepted_at']),
        ]

    def __str__(self):
        return f"{self.user.email} {self.event} {self.accepted_at.isoformat()}"


class PendingSignup(models.Model):
    """Stores registration data until phone verification completes.

    A User row should not exist until the phone is verified.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.CharField(max_length=128, unique=True, db_index=True)

    email = models.EmailField(db_index=True)
    password_hash = models.CharField(max_length=256)

    first_name = models.CharField(max_length=100, blank=True)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)

    code_hash = models.CharField(max_length=256)
    expires_at = models.DateTimeField(db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pending_signups'
        indexes = [
            models.Index(fields=['email', 'created_at']),
            models.Index(fields=['phone', 'created_at']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"PendingSignup<{self.email}>"


class PendingEmailSignup(models.Model):
    """Stores email-only registration data until email verification completes."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    password_hash = models.CharField(max_length=256)

    first_name = models.CharField(max_length=100, blank=True)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)

    accepted_documents = models.JSONField(default=dict, blank=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    is_bot_suspected = models.BooleanField(
        default=False,
        db_index=True,
        help_text='Exclude suspected automated signups from funnel metrics until reviewed.',
    )
    bot_signals = models.JSONField(
        default=list,
        blank=True,
        help_text='Suspicious indicators collected during admin review.',
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pending_email_signups'
        indexes = [
            models.Index(fields=['email', 'created_at']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"PendingEmailSignup<{self.email}>"

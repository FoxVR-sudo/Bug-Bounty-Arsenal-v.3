from django.db import models
from django.conf import settings


class Plan(models.Model):
    """Subscription plan model - Updated v3.0"""

    PLAN_NAMES = [
        ('free', 'Free'),
        ('pro', 'Pro'),
        ('enterprise', 'Enterprise'),
    ]

    name = models.CharField(max_length=50, unique=True, choices=PLAN_NAMES)
    display_name = models.CharField(max_length=100)
    description = models.TextField(blank=True, help_text='Plan description for landing page')
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00, help_text='Monthly price in USD')
    price_yearly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        blank=True,
        null=True,
        help_text='Yearly price in USD (optional; shown when yearly billing is selected)',
    )

    # NEW v3.0: Scan limits (simplified)
    scans_per_day = models.IntegerField(default=3, help_text='Daily scan limit (-1 = unlimited)')
    scans_per_month = models.IntegerField(default=10, help_text='Monthly scan limit (-1 = unlimited)')
    concurrent_scans = models.IntegerField(default=1, help_text='Number of concurrent scans allowed')

    # Storage limits
    storage_limit_mb = models.IntegerField(default=100, help_text='Storage limit in MB for scan results')
    retention_days = models.IntegerField(default=7, help_text='How many days to keep scan results')

    # NEW v3.0: Scanner access (NOT detector limits, all plans see all scanners)
    # Access is controlled by scan count, not detector type
    allow_dangerous_tools = models.BooleanField(default=False,
                                                help_text='Allow Nuclei, custom payloads (Enterprise only)')

    # NEW v3.0: Team collaboration
    allow_teams = models.BooleanField(default=False, help_text='Enable team features (Pro & Enterprise)')
    max_team_members = models.IntegerField(default=0, help_text='Maximum team members (0 = no teams)')

    # NEW v3.0: Integrations
    allow_integrations = models.BooleanField(default=False,
                                             help_text='Enable third-party integrations (Pro & Enterprise)')
    max_integrations = models.IntegerField(default=0, help_text='Maximum active integrations')

    # Features
    features = models.JSONField(default=list, help_text='List of feature names for display')

    # Status
    is_active = models.BooleanField(default=True)
    is_popular = models.BooleanField(default=False, help_text='Show "Most Popular" badge')
    order = models.IntegerField(default=0, help_text='Display order on pricing page')

    # Stripe product ID
    stripe_price_id = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text='Legacy Stripe Price ID (monthly). Prefer stripe_price_id_monthly/stripe_price_id_yearly.',
    )
    stripe_price_id_monthly = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text='Stripe Price ID (monthly)',
    )
    stripe_price_id_yearly = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text='Stripe Price ID (yearly)',
    )
    stripe_product_id = models.CharField(max_length=100, blank=True, null=True, help_text='Stripe Product ID')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'plans'
        ordering = ['order', 'price']

    def __str__(self):
        return self.display_name


class PlanScanCategoryOverride(models.Model):
    """Per-plan enable/disable overrides for scan categories (recon/web/api/vuln/mobile)."""

    plan = models.ForeignKey(Plan, on_delete=models.CASCADE, related_name='scan_category_overrides')
    category = models.ForeignKey('scans.ScanCategory', on_delete=models.CASCADE, related_name='plan_overrides')
    is_allowed = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'plan_scan_category_overrides'
        unique_together = [['plan', 'category']]
        indexes = [
            models.Index(fields=['plan', 'category']),
        ]

    def __str__(self):
        return f"{self.plan.name}: {self.category.name} -> {'allowed' if self.is_allowed else 'blocked'}"


class Subscription(models.Model):
    """User subscription model"""

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('cancelled', 'Cancelled'),
        ('expired', 'Expired'),
        ('trialing', 'Trialing'),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subscription')
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name='subscriptions')

    # Stripe integration
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    stripe_subscription_id = models.CharField(max_length=100, blank=True)

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    cancel_at_period_end = models.BooleanField(default=False)

    # Usage tracking (NEW v3.0: monthly tracking added)
    scans_used_today = models.IntegerField(default=0)
    scans_used_this_month = models.IntegerField(default=0)
    last_scan_reset = models.DateField(auto_now_add=True)
    last_monthly_reset = models.DateField(null=True, blank=True)  # Changed to allow null for migration

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'subscriptions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['stripe_customer_id']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.plan.name} ({self.status})"

    def reset_daily_usage(self):
        """Reset daily scan usage"""
        from datetime import date
        today = date.today()
        if self.last_scan_reset is None or self.last_scan_reset < today:
            self.scans_used_today = 0
            self.last_scan_reset = today
            self.save()

    def reset_monthly_usage(self):
        """Reset monthly scan usage (NEW v3.0)"""
        from datetime import date
        today = date.today()
        # Reset if it's a new month
        if (
            self.last_monthly_reset is None
            or self.last_monthly_reset.month != today.month
            or self.last_monthly_reset.year != today.year
        ):
            self.scans_used_this_month = 0
            self.last_monthly_reset = today
            self.save()

    def can_start_scan(self):
        """Check if user can start a new scan (NEW v3.0: checks both daily and monthly)"""
        # Subscription must be usable.
        if self.status not in ('active', 'trialing'):
            return False, 'No active subscription found. Please subscribe to a plan.'

        self.reset_daily_usage()
        self.reset_monthly_usage()

        # Check concurrent scan limit
        try:
            from scans.models import Scan
            concurrent_limit = self.plan.concurrent_scans
            if concurrent_limit != -1:
                active_count = Scan.objects.filter(
                    user=self.user,
                    status__in=['pending', 'running'],
                ).count()
                if active_count >= concurrent_limit:
                    return False, f"Concurrent scan limit reached ({concurrent_limit} concurrent scans)"
        except Exception:
            # If scans app is not ready for import (migrations/tests), don't block.
            pass

        # Check daily limit
        daily_limit = self.plan.scans_per_day
        if daily_limit != -1 and self.scans_used_today >= daily_limit:
            return False, f"Daily limit reached ({daily_limit} scans/day)"

        # Check monthly limit
        monthly_limit = self.plan.scans_per_month
        if monthly_limit != -1 and self.scans_used_this_month >= monthly_limit:
            return False, f"Monthly limit reached ({monthly_limit} scans/month)"

        return True, "OK"

    def increment_scan_usage(self):
        """Increment scan counter (NEW v3.0: both daily and monthly)"""
        self.scans_used_today += 1
        self.scans_used_this_month += 1
        self.save()

    def can_use_dangerous_tools(self):
        """Check if user can use Nuclei/payloads (NEW v3.0: Enterprise only)"""
        return self.plan.allow_dangerous_tools

    def can_create_team(self):
        """Check if user can create teams (NEW v3.0: Pro & Enterprise)"""
        return self.plan.allow_teams

    def can_add_integration(self):
        """Check if user can add integrations (NEW v3.0: Pro & Enterprise)"""
        return self.plan.allow_integrations


class Payment(models.Model):
    """Payment transaction model"""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('succeeded', 'Succeeded'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='payments')
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='payments')

    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='usd')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Stripe IDs
    stripe_payment_intent_id = models.CharField(max_length=100, blank=True, null=True)
    stripe_invoice_id = models.CharField(max_length=100, blank=True, null=True)

    # Metadata
    description = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'payments'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['stripe_payment_intent_id']),
        ]

    def __str__(self):
        return f"{self.user.email} - ${self.amount} ({self.status})"


class EnterpriseCustomer(models.Model):
    """
    Enterprise customer billing information - for manual invoicing
    Used when Enterprise clients pay via bank transfer instead of Stripe
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='enterprise_customer')
    subscription = models.OneToOneField(Subscription, on_delete=models.CASCADE, null=True, blank=True)

    # Company Details
    company_name = models.CharField(max_length=200, help_text='Legal company name')
    vat_number = models.CharField(max_length=50, blank=True, help_text='VAT/ДДС number')
    registration_number = models.CharField(
        max_length=50,
        blank=True,
        help_text='Company registration number (ЕИК/БУЛСТАТ)')

    # Billing Address
    billing_address = models.TextField(help_text='Street address')
    billing_city = models.CharField(max_length=100)
    billing_country = models.CharField(max_length=100, default='Bulgaria')
    billing_zip = models.CharField(max_length=20, blank=True)

    # Billing Contacts
    billing_email = models.EmailField(help_text='Email for invoices')
    billing_phone = models.CharField(max_length=50, blank=True)
    accounting_contact_name = models.CharField(max_length=200, blank=True, help_text='Name of accounting person')
    accounting_contact_email = models.EmailField(blank=True, help_text='Separate accounting email')

    # Payment Terms
    PAYMENT_TERMS_CHOICES = [
        ('net_15', 'Net 15 days'),
        ('net_30', 'Net 30 days'),
        ('net_60', 'Net 60 days'),
        ('prepaid', 'Prepaid'),
    ]
    payment_terms = models.CharField(max_length=20, choices=PAYMENT_TERMS_CHOICES, default='net_30')

    INVOICE_FREQUENCY_CHOICES = [
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('yearly', 'Yearly'),
    ]
    invoice_frequency = models.CharField(max_length=20, choices=INVOICE_FREQUENCY_CHOICES, default='monthly')

    custom_monthly_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=299.00,
        help_text='Custom negotiated price per month')

    # Invoice Settings
    po_number_required = models.BooleanField(default=False, help_text='Require Purchase Order number')
    custom_invoice_notes = models.TextField(blank=True, help_text='Custom notes to include in all invoices')

    # Payment Method
    use_stripe = models.BooleanField(default=False, help_text='True = Stripe auto-billing, False = manual invoicing')
    stripe_customer_id = models.CharField(max_length=100, blank=True)

    # Status
    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'enterprise_customers'
        verbose_name = 'Enterprise Customer'
        verbose_name_plural = 'Enterprise Customers'

    def __str__(self):
        return f"{self.company_name} ({self.user.email})"


class Invoice(models.Model):
    """
    Invoice tracking for Enterprise customers
    Supports both manual and Stripe invoicing
    """

    enterprise_customer = models.ForeignKey(EnterpriseCustomer, on_delete=models.CASCADE, related_name='invoices')
    subscription = models.ForeignKey(Subscription, on_delete=models.SET_NULL, null=True, blank=True)

    # Invoice Details
    invoice_number = models.CharField(max_length=50, unique=True, help_text='e.g., INV-2025-001')
    invoice_date = models.DateField()
    due_date = models.DateField()
    period_start = models.DateField(help_text='Billing period start')
    period_end = models.DateField(help_text='Billing period end')

    # Amounts
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, help_text='Amount before tax')
    vat_rate = models.DecimalField(max_digits=5, decimal_places=2, default=20.00, help_text='VAT percentage')
    vat_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text='Calculated VAT amount')
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, help_text='Total with VAT')

    # Status
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('sent', 'Sent'),
        ('paid', 'Paid'),
        ('overdue', 'Overdue'),
        ('cancelled', 'Cancelled'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')

    # Files
    pdf_file = models.FileField(upload_to='invoices/%Y/%m/', blank=True, help_text='Generated invoice PDF')

    # Tracking
    sent_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    payment_method = models.CharField(max_length=50, blank=True, help_text='e.g., Bank Transfer, Stripe')

    # Optional
    po_number = models.CharField(
        max_length=100,
        blank=True,
        verbose_name='PO Number',
        help_text='Purchase Order number')
    notes = models.TextField(blank=True, help_text='Internal notes')

    # Stripe Integration
    stripe_invoice_id = models.CharField(max_length=100, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'invoices'
        ordering = ['-invoice_date']
        indexes = [
            models.Index(fields=['enterprise_customer', 'status']),
            models.Index(fields=['invoice_number']),
        ]

    def __str__(self):
        return f"{self.invoice_number} - {self.enterprise_customer.company_name} (${self.total_amount})"

    def save(self, *args, **kwargs):
        # Auto-calculate VAT and total
        if self.subtotal:
            self.vat_amount = (self.subtotal * self.vat_rate) / 100
            self.total_amount = self.subtotal + self.vat_amount
        super().save(*args, **kwargs)

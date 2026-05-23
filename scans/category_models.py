"""
Scanner Category and Detector Configuration Models for v3.0
    Organizes 40+ detectors into 5 scan categories with plan-based restrictions.
"""
from django.db import models


class ScanCategory(models.Model):
    """
    Scanner categories for organizing detectors into logical groups.

    Categories:
    - Recon: Subdomain enumeration, DNS, WHOIS, tech detection
    - Web: XSS, SQLi, CSRF, CORS, security headers, open redirect
    - API: GraphQL, REST API, JWT, OAuth vulnerabilities
    - Vuln: CVE scanning, version detection, known vulnerabilities
    - Mobile: Android/iOS security testing

    """

    CATEGORY_CHOICES = [
        ('recon', 'Reconnaissance Scan'),
        ('web', 'Web Application Scan'),
        ('api', 'API Security Scan'),
        ('vuln', 'Vulnerability Scan'),
        ('mobile', 'Mobile Security Scan'),
    ]

    PLAN_CHOICES = [
        ('free', 'Free Plan'),
        ('pro', 'Pro Plan'),
        ('enterprise', 'Enterprise Plan'),
    ]

    name = models.CharField(max_length=50, choices=CATEGORY_CHOICES, unique=True)
    display_name = models.CharField(max_length=100)
    description = models.TextField()
    required_plan = models.CharField(
        max_length=20,
        choices=PLAN_CHOICES,
        default='free',
        help_text='Minimum plan required to use this category'
    )
    icon = models.CharField(
        max_length=50,
        default='🔍',
        help_text='Emoji icon for UI display'
    )
    is_active = models.BooleanField(default=True)
    detector_count = models.IntegerField(
        default=0,
        help_text='Number of detectors in this category (auto-calculated)'
    )
    order = models.IntegerField(default=0, help_text='Display order in UI')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Scan Category'
        verbose_name_plural = 'Scan Categories'
        ordering = ['order', 'name']
        db_table = 'scan_categories'

    def __str__(self):
        return f"{self.display_name} ({self.required_plan})"

    def update_detector_count(self):
        """Recalculate detector count from associated detectors"""
        self.detector_count = self.detectors.filter(is_active=True).count()
        self.save(update_fields=['detector_count'])

    def get_detectors(self):
        """Get all active detectors for this category"""
        return self.detectors.filter(is_active=True).order_by('execution_order', 'name')

    def can_be_used_by_plan(self, plan_name):
        """Check if a plan can use this category"""
        plan_hierarchy = {'free': 0, 'pro': 1, 'enterprise': 2}
        return plan_hierarchy.get(plan_name, 0) >= plan_hierarchy.get(self.required_plan, 0)


class DetectorConfig(models.Model):
    """
    Configuration for individual detectors with category mappings.
    Each detector can belong to multiple categories.
    """

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]

    # Unique identifier (matches Python module name in detectors/)
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text='Python module name (e.g., xss_pattern_detector)'
    )
    display_name = models.CharField(max_length=150)
    description = models.TextField()

    # Category associations (one detector can be in multiple categories)
    categories = models.ManyToManyField(
        ScanCategory,
        related_name='detectors',
        help_text='Categories this detector belongs to'
    )

    # Detector metadata
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default='medium',
        help_text='Maximum severity of vulnerabilities this detector can find'
    )
    tags = models.JSONField(
        default=list,
        help_text='Tags for filtering (e.g., ["injection", "owasp-top10"])'
    )

    # Security classification
    is_dangerous = models.BooleanField(
        default=False,
        help_text='Requires Enterprise plan (nuclei, brute force, custom payloads)'
    )
    requires_oob = models.BooleanField(
        default=False,
        help_text='Requires out-of-band interaction (Interactsh, Burp Collaborator)'
    )

    # Execution configuration
    execution_order = models.IntegerField(
        default=100,
        help_text='Order of execution (lower runs first)'
    )
    timeout_seconds = models.IntegerField(
        default=30,
        help_text='Maximum execution time per target'
    )
    max_concurrency = models.IntegerField(
        default=10,
        help_text='Maximum concurrent requests'
    )

    # Status
    is_active = models.BooleanField(default=True)
    is_beta = models.BooleanField(
        default=False,
        help_text='Beta features may have bugs or incomplete functionality'
    )

    # Statistics (updated by scans)
    total_executions = models.IntegerField(default=0)
    total_findings = models.IntegerField(default=0)
    average_execution_time = models.FloatField(default=0.0, help_text='In seconds')
    last_executed_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Detector Configuration'
        verbose_name_plural = 'Detector Configurations'
        ordering = ['execution_order', 'name']
        db_table = 'detector_configs'

    def __str__(self):
        dangerous_flag = ' [DANGEROUS]' if self.is_dangerous else ''
        return f"{self.display_name}{dangerous_flag}"

    def clean(self):
        """Validate detector configuration"""
        super().clean()

        # Custom scan should have all detectors
        if self.categories.filter(name='custom').exists():
            if not self.is_dangerous:
                # All detectors should be in custom scan
                pass

    def get_category_names(self):
        """Get list of category names this detector belongs to"""
        return list(self.categories.values_list('name', flat=True))

    def increment_stats(self, execution_time, findings_count):
        """Update execution statistics"""
        self.total_executions += 1
        self.total_findings += findings_count

        # Calculate running average
        if self.average_execution_time == 0:
            self.average_execution_time = execution_time
        else:
            self.average_execution_time = (
                (self.average_execution_time * (self.total_executions - 1) + execution_time)
                / self.total_executions
            )

        from django.utils import timezone
        self.last_executed_at = timezone.now()
        self.save(update_fields=[
            'total_executions',
            'total_findings',
            'average_execution_time',
            'last_executed_at'
        ])


class CategoryDetectorOrder(models.Model):
    """
    Custom execution order for detectors within specific categories.
    Allows different execution orders for the same detector in different categories.
    """
    category = models.ForeignKey(ScanCategory, on_delete=models.CASCADE)
    detector = models.ForeignKey(DetectorConfig, on_delete=models.CASCADE)
    order = models.IntegerField(default=100)
    is_enabled = models.BooleanField(
        default=True,
        help_text='Can be disabled per category without removing from category'
    )

    class Meta:
        unique_together = [['category', 'detector']]
        ordering = ['order']
        db_table = 'category_detector_orders'

    def __str__(self):
        return f"{self.category.name} → {self.detector.name} (order: {self.order})"

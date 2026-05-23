from django import forms
from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from scans.category_models import ScanCategory

from .models import Plan, PlanScanCategoryOverride, Subscription, EnterpriseCustomer, Invoice


def _plan_level(plan_name: str) -> int:
    plan_hierarchy = {'free': 0, 'pro': 1, 'enterprise': 2}
    return plan_hierarchy.get((plan_name or '').lower(), 0)


def _default_allowed_category_ids(plan: Plan) -> set[int]:
    """Compute default allowed scan categories for a plan from required_plan."""
    level = _plan_level(plan.name)

    allowed_categories: set[int] = set()
    for cat in ScanCategory.objects.filter(is_active=True).only('id', 'required_plan'):
        if level >= _plan_level(cat.required_plan):
            allowed_categories.add(cat.id)
    return allowed_categories


class PlanAdminForm(forms.ModelForm):
    scan_categories = forms.ModelMultipleChoiceField(
        queryset=ScanCategory.objects.filter(is_active=True).order_by('order', 'name'),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text=(
            'Enable/disable scan categories for this plan. Unchecked = disabled. '
            'Defaults come from required_plan.'
        ),
    )

    class Meta:
        model = Plan
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        plan = self.instance
        if not getattr(plan, 'pk', None):
            return

        # Initial checkbox state = defaults + overrides.
        default_allowed = _default_allowed_category_ids(plan)
        overrides = {
            o.category_id: bool(o.is_allowed)
            for o in PlanScanCategoryOverride.objects.filter(plan=plan).only('category_id', 'is_allowed')
        }

        enabled_ids: list[int] = []
        for cat in ScanCategory.objects.filter(is_active=True).only('id'):
            allowed = cat.id in default_allowed
            if cat.id in overrides:
                allowed = overrides[cat.id]
            if allowed:
                enabled_ids.append(cat.id)

        self.fields['scan_categories'].initial = enabled_ids


@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    """Plan admin with full control over all settings - Updated v3.0"""

    form = PlanAdminForm

    list_display = [
        'display_name',
        'name',
        'price_display',
        'scans_per_day',
        'scans_per_month',
        'allow_dangerous_tools',
        'allow_teams',
        'allow_integrations',
        'is_active',
        'is_popular',
        'order']
    list_filter = ['is_active', 'is_popular', 'allow_dangerous_tools', 'allow_teams', 'allow_integrations']
    search_fields = ['name', 'display_name', 'description']
    list_editable = ['is_active', 'is_popular', 'order']
    ordering = ['order', 'price']

    fieldsets = (
        ('Basic Information', {
            'fields': (
                'name',
                'display_name',
                'description',
                'price',
                'price_yearly',
                'is_active',
                'is_popular',
                'order',
            )
        }),
        ('Stripe Integration', {
            'fields': ('stripe_product_id', 'stripe_price_id_monthly', 'stripe_price_id_yearly'),
            'description': 'Optional: map this plan to existing Stripe Product/Price IDs (monthly/yearly)',
            'classes': ('collapse',)
        }),
        ('Stripe (Legacy)', {
            'fields': ('stripe_price_id',),
            'classes': ('collapse',)
        }),
        ('Scan Limits (v3.0)', {
            'fields': ('scans_per_day', 'scans_per_month', 'concurrent_scans'),
            'description': (
                'FREE: 3/day 10/month | PRO: 100/day 500/month | ENTERPRISE: -1 (unlimited)'
            ),
        }),
        ('Storage & Retention', {
            'fields': ('storage_limit_mb', 'retention_days')
        }),
        ('NEW v3.0: Access Control', {
            'fields': (
                'allow_dangerous_tools',
                'allow_teams',
                'max_team_members',
                'allow_integrations',
                'max_integrations',
                'scan_categories',
            ),
            'description': (
                'Dangerous tools (Nuclei/payloads): Enterprise only | Teams: Pro & Enterprise | Integrations: '
                'Pro & Enterprise'
            ),
        }),
        ('Features List', {
            'fields': ('features',),
            'description': 'List of features to display on pricing page'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    readonly_fields = ['created_at', 'updated_at']

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)

        # Persist only diffs vs default into PlanScanCategoryOverride.
        try:
            enabled = set(form.cleaned_data.get('scan_categories', []).values_list('id', flat=True))
        except Exception:
            enabled = set()

        default_allowed = _default_allowed_category_ids(obj)
        current_overrides = {
            o.category_id: o
            for o in PlanScanCategoryOverride.objects.filter(plan=obj).select_related(None)
        }

        active_categories = list(ScanCategory.objects.filter(is_active=True).only('id'))
        for cat in active_categories:
            desired_allowed = cat.id in enabled
            default_is_allowed = cat.id in default_allowed

            if desired_allowed == default_is_allowed:
                # No override needed; delete if exists.
                if cat.id in current_overrides:
                    current_overrides[cat.id].delete()
                continue

            override = current_overrides.get(cat.id)
            if override is None:
                PlanScanCategoryOverride.objects.create(plan=obj, category_id=cat.id, is_allowed=desired_allowed)
            else:
                if override.is_allowed != desired_allowed:
                    override.is_allowed = desired_allowed
                    override.save(update_fields=['is_allowed', 'updated_at'])

    def price_display(self, obj):
        if obj.price == 0:
            return format_html('<span style="color: green; font-weight: bold;">{}</span>', 'FREE')
        return format_html('<span style="font-weight: bold;">${}/mo</span>', obj.price)
    price_display.short_description = 'Price'


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    """Subscription admin with usage tracking"""

    list_display = ['user_email', 'plan_name', 'status', 'usage_display', 'storage_info', 'created_at']
    list_filter = ['status', 'plan__name', 'created_at']
    search_fields = ['user__email', 'stripe_customer_id', 'stripe_subscription_id']
    readonly_fields = ['created_at', 'updated_at', 'last_scan_reset']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']

    fieldsets = (
        ('User & Plan', {
            'fields': ('user', 'plan', 'status')
        }),
        ('Stripe Integration', {
            'fields': ('stripe_customer_id', 'stripe_subscription_id'),
            'classes': ('collapse',)
        }),
        ('Billing Period', {
            'fields': ('current_period_start', 'current_period_end', 'cancel_at_period_end')
        }),
        ('Usage Tracking', {
            'fields': ('scans_used_today',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'last_scan_reset'),
            'classes': ('collapse',)
        }),
    )

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User'
    user_email.admin_order_field = 'user__email'

    def plan_name(self, obj):
        color = 'green' if obj.plan.price == 0 else 'blue'
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.plan.display_name)
    plan_name.short_description = 'Plan'
    plan_name.admin_order_field = 'plan__name'

    def usage_display(self, obj):
        daily_limit = obj.plan.scans_per_day
        used = obj.scans_used_today

        if daily_limit == -1:
            return format_html('<span style="color: green;">{} / ∞</span>', used)

        percentage = (used / daily_limit * 100) if daily_limit > 0 else 0
        color = 'red' if percentage >= 90 else ('orange' if percentage >= 70 else 'green')

        return format_html('<span style="color: {};">{} / {}</span>', color, used, daily_limit)
    usage_display.short_description = 'Daily Usage'

    def storage_info(self, obj):
        return f'{obj.plan.storage_limit_mb} MB limit'
    storage_info.short_description = 'Storage'

    actions = ['reset_daily_usage', 'activate_subscriptions', 'cancel_subscriptions']

    def reset_daily_usage(self, request, queryset):
        for sub in queryset:
            sub.reset_daily_usage()
        self.message_user(request, f"✅ Reset daily usage for {queryset.count()} subscriptions")
    reset_daily_usage.short_description = "Reset daily scan usage"

    def activate_subscriptions(self, request, queryset):
        queryset.update(status='active')
        self.message_user(request, f'✅ Activated {queryset.count()} subscriptions')
    activate_subscriptions.short_description = 'Activate selected subscriptions'

    def cancel_subscriptions(self, request, queryset):
        queryset.update(status='cancelled', cancel_at_period_end=True)
        self.message_user(request, f'⚠️ Cancelled {queryset.count()} subscriptions')
    cancel_subscriptions.short_description = 'Cancel selected subscriptions'


@admin.register(EnterpriseCustomer)
class EnterpriseCustomerAdmin(admin.ModelAdmin):
    """Enterprise customer billing management"""

    list_display = [
        'company_name',
        'user_email',
        'custom_monthly_price',
        'payment_terms',
        'invoice_frequency',
        'is_active',
        'created_at']
    list_filter = ['is_active', 'payment_terms', 'invoice_frequency', 'billing_country']
    search_fields = ['company_name', 'user__email', 'vat_number', 'registration_number', 'billing_email']
    list_editable = ['is_active']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = (
        ('Company Information', {
            'fields': ('user', 'subscription', 'company_name', 'vat_number', 'registration_number', 'is_active')
        }),
        ('Billing Address', {
            'fields': ('billing_address', 'billing_city', 'billing_country', 'billing_zip')
        }),
        ('Billing Contacts', {
            'fields': ('billing_email', 'billing_phone', 'accounting_contact_name', 'accounting_contact_email')
        }),
        ('Payment Terms & Pricing', {
            'fields': ('custom_monthly_price', 'payment_terms', 'invoice_frequency')
        }),
        ('Invoice Settings', {
            'fields': ('po_number_required', 'custom_invoice_notes', 'use_stripe', 'stripe_customer_id')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'

    actions = ['generate_monthly_invoice']

    def generate_monthly_invoice(self, request, queryset):
        """Generate invoice for selected customers"""
        from datetime import date, timedelta
        from dateutil.relativedelta import relativedelta

        count = 0
        for customer in queryset:
            if not customer.is_active:
                continue

            # Generate invoice for current month
            today = date.today()
            invoice_date = today
            period_start = today.replace(day=1)
            period_end = (period_start + relativedelta(months=1)) - timedelta(days=1)

            # Calculate due date based on payment terms
            if customer.payment_terms == 'net_15':
                due_date = invoice_date + timedelta(days=15)
            elif customer.payment_terms == 'net_30':
                due_date = invoice_date + timedelta(days=30)
            elif customer.payment_terms == 'net_60':
                due_date = invoice_date + timedelta(days=60)
            else:  # prepaid
                due_date = invoice_date

            # Generate invoice number
            year_month = today.strftime('%Y%m')
            existing_count = Invoice.objects.filter(invoice_number__startswith=f'INV-{year_month}').count()
            invoice_number = f'INV-{year_month}-{existing_count + 1:03d}'

            # Create invoice
            Invoice.objects.create(
                enterprise_customer=customer,
                subscription=customer.subscription,
                invoice_number=invoice_number,
                invoice_date=invoice_date,
                due_date=due_date,
                period_start=period_start,
                period_end=period_end,
                subtotal=customer.custom_monthly_price,
                vat_rate=20.00,  # Default VAT
                status='draft'
            )
            count += 1

        self.message_user(request, f'✅ Generated {count} invoices')
    generate_monthly_invoice.short_description = '📄 Generate monthly invoice'


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    """Invoice management with PDF generation"""

    list_display = [
        'invoice_number',
        'company_name',
        'invoice_date',
        'due_date',
        'total_display',
        'status',
        'sent_at',
        'paid_at']
    list_filter = ['status', 'invoice_date', 'sent_at', 'paid_at']
    search_fields = ['invoice_number', 'enterprise_customer__company_name', 'po_number']
    readonly_fields = ['created_at', 'updated_at', 'vat_amount', 'total_amount']
    date_hierarchy = 'invoice_date'
    ordering = ['-invoice_date']

    fieldsets = (
        ('Invoice Details', {
            'fields': ('enterprise_customer', 'subscription', 'invoice_number', 'invoice_date', 'due_date')
        }),
        ('Billing Period', {
            'fields': ('period_start', 'period_end')
        }),
        ('Amounts', {
            'fields': ('subtotal', 'vat_rate', 'vat_amount', 'total_amount')
        }),
        ('Status & Tracking', {
            'fields': ('status', 'sent_at', 'paid_at', 'payment_method')
        }),
        ('Optional', {
            'fields': ('po_number', 'notes', 'pdf_file', 'stripe_invoice_id'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def company_name(self, obj):
        return obj.enterprise_customer.company_name
    company_name.short_description = 'Company'
    company_name.admin_order_field = 'enterprise_customer__company_name'

    def total_display(self, obj):
        color = 'green' if obj.status == 'paid' else ('red' if obj.status == 'overdue' else 'orange')
        return format_html('<span style="color: {}; font-weight: bold;">${}</span>', color, obj.total_amount)
    total_display.short_description = 'Total Amount'

    actions = ['mark_as_sent', 'mark_as_paid', 'mark_as_overdue']

    def mark_as_sent(self, request, queryset):
        queryset.update(status='sent', sent_at=timezone.now())
        self.message_user(request, f'✅ Marked {queryset.count()} invoices as sent')
    mark_as_sent.short_description = '📧 Mark as Sent'

    def mark_as_paid(self, request, queryset):
        queryset.update(status='paid', paid_at=timezone.now())
        self.message_user(request, f'✅ Marked {queryset.count()} invoices as paid')
    mark_as_paid.short_description = '💰 Mark as Paid'

    def mark_as_overdue(self, request, queryset):
        queryset.update(status='overdue')
        self.message_user(request, f'⚠️ Marked {queryset.count()} invoices as overdue')
    mark_as_overdue.short_description = '⏰ Mark as Overdue'

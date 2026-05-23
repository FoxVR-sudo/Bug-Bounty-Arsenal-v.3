import re
from datetime import timedelta

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.db.models import Count
from django.utils import timezone
from django.utils.html import format_html, format_html_join

from .models import PendingEmailSignup, User
from .audit_models import ScanAuditLog
from .team_models import Team, TeamMember, TeamInvitation
from .integration_models import Integration


_FUNNEL_PERIODS = (
    ('24h', 'Last 24 hours', timedelta(hours=24)),
    ('7d', 'Last 7 days', timedelta(days=7)),
    ('30d', 'Last 30 days', timedelta(days=30)),
    ('all', 'All time', None),
)


def _query_string_with(request, **updates):
    params = request.GET.copy()
    for key, value in updates.items():
        if value is None:
            params.pop(key, None)
            continue
        params[key] = value
    encoded = params.urlencode()
    return f'?{encoded}' if encoded else '?'


def _period_config(period_key):
    for key, label, delta in _FUNNEL_PERIODS:
        if key == period_key:
            return label, delta
    return _FUNNEL_PERIODS[1][1], _FUNNEL_PERIODS[1][2]


def _format_rate(numerator, denominator):
    if not denominator:
        return 'n/a'
    return f'{(numerator / denominator) * 100:.1f}%'


def _generated_email_local_part(local_part):
    cleaned = ''.join(char for char in (local_part or '').lower() if char.isalnum())
    if len(cleaned) < 12:
        return False

    digit_count = sum(char.isdigit() for char in cleaned)
    digit_ratio = digit_count / len(cleaned)
    return bool(re.fullmatch(r'[a-z0-9]{12,}', cleaned)) and digit_count >= 3 and digit_ratio >= 0.25


class PendingEmailSignupStateFilter(admin.SimpleListFilter):
    title = 'pending state'
    parameter_name = 'pending_state'

    def lookups(self, request, model_admin):
        return (
            ('active', 'Active'),
            ('expired', 'Expired'),
        )

    def queryset(self, request, queryset):
        now = timezone.now()
        if self.value() == 'active':
            return queryset.filter(expires_at__gt=now)
        if self.value() == 'expired':
            return queryset.filter(expires_at__lte=now)
        return queryset


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User admin - Updated v3.0"""

    list_display = [
        'email',
        'full_name',
        'phone',
        'phone_verified',
        'company_name',
        'company_verified',
        'is_admin',
        'is_verified',
        'registration_ip',
        'registration_location',
        'registration_security_status',
        'last_seen_ip',
        'last_seen_location',
        'last_seen_security_status',
        'is_active',
        'created_at',
    ]
    list_filter = [
        'is_admin',
        'is_verified',
        'phone_verified',
        'company_verified',
        'is_active',
        'is_staff',
        'created_at',
    ]
    search_fields = [
        'email',
        'full_name',
        'first_name',
        'last_name',
        'phone',
        'company_name',
        'registration_ip',
        'last_seen_ip',
    ]
    ordering = ['-created_at']

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (
            'Personal info',
            {'fields': ('first_name', 'middle_name', 'last_name', 'full_name', 'address')},
        ),
        (
            'Phone verification',
            {
                'fields': (
                    'phone',
                    'phone_verified',
                    'phone_verification_code',
                    'phone_verification_expires',
                )
            },
        ),
        (
            'Company info (Enterprise)',
            {
                'fields': (
                    'company_name',
                    'company_registration_number',
                    'company_address',
                    'company_country',
                    'company_verified',
                    'company_verification_date',
                )
            },
        ),
        (
            'Permissions',
            {
                'fields': (
                    'is_admin',
                    'is_verified',
                    'is_active',
                    'is_staff',
                    'is_superuser',
                    'groups',
                    'user_permissions',
                )
            },
        ),
        ('Stripe', {'fields': ('stripe_customer_id',)}),
        (
            'IP & Location',
            {
                'fields': (
                    'registration_ip',
                    'registration_city',
                    'registration_country',
                    'registration_latitude',
                    'registration_longitude',
                    'registration_map_link',
                    'registration_security_status',
                    'registration_is_anonymous',
                    'registration_is_proxy',
                    'registration_is_vpn',
                    'registration_is_tor',
                    'registration_is_hosting',
                    'last_seen_ip',
                    'last_seen_city',
                    'last_seen_country',
                    'last_seen_latitude',
                    'last_seen_longitude',
                    'last_seen_map_link',
                    'last_seen_security_status',
                    'last_seen_is_anonymous',
                    'last_seen_is_proxy',
                    'last_seen_is_vpn',
                    'last_seen_is_tor',
                    'last_seen_is_hosting',
                )
            },
        ),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )

    add_fieldsets = (
        (
            None,
            {
                'classes': ('wide',),
                'fields': (
                    'email',
                    'password1',
                    'password2',
                    'first_name',
                    'middle_name',
                    'last_name',
                    'phone',
                ),
            },
        ),
    )

    readonly_fields = [
        'created_at',
        'updated_at',
        'last_login',
        'full_name',
        'company_verification_date',
        'registration_ip',
        'registration_city',
        'registration_country',
        'registration_latitude',
        'registration_longitude',
        'registration_map_link',
        'registration_security_status',
        'registration_is_anonymous',
        'registration_is_proxy',
        'registration_is_vpn',
        'registration_is_tor',
        'registration_is_hosting',
        'last_seen_ip',
        'last_seen_city',
        'last_seen_country',
        'last_seen_latitude',
        'last_seen_longitude',
        'last_seen_map_link',
        'last_seen_security_status',
        'last_seen_is_anonymous',
        'last_seen_is_proxy',
        'last_seen_is_vpn',
        'last_seen_is_tor',
        'last_seen_is_hosting',
    ]

    def registration_location(self, obj):
        return self._location_html(
            obj.registration_city,
            obj.registration_country,
            obj.registration_latitude,
            obj.registration_longitude,
        )
    registration_location.short_description = 'Registration Location'

    def last_seen_location(self, obj):
        return self._location_html(
            obj.last_seen_city,
            obj.last_seen_country,
            obj.last_seen_latitude,
            obj.last_seen_longitude,
        )
    last_seen_location.short_description = 'Last Seen Location'

    def registration_map_link(self, obj):
        return self._map_link(obj.registration_latitude, obj.registration_longitude)
    registration_map_link.short_description = 'Registration Map'

    def registration_security_status(self, obj):
        return self._security_status(
            obj.registration_is_anonymous,
            obj.registration_is_proxy,
            obj.registration_is_vpn,
            obj.registration_is_tor,
            obj.registration_is_hosting,
        )
    registration_security_status.short_description = 'Registration Network'

    def last_seen_map_link(self, obj):
        return self._map_link(obj.last_seen_latitude, obj.last_seen_longitude)
    last_seen_map_link.short_description = 'Last Seen Map'

    def last_seen_security_status(self, obj):
        return self._security_status(
            obj.last_seen_is_anonymous,
            obj.last_seen_is_proxy,
            obj.last_seen_is_vpn,
            obj.last_seen_is_tor,
            obj.last_seen_is_hosting,
        )
    last_seen_security_status.short_description = 'Last Seen Network'

    def _location_html(self, city, country, latitude, longitude):
        label_parts = [city, country]
        label = ', '.join(part for part in label_parts if part)
        if not label and latitude is not None and longitude is not None:
            label = f'{latitude:.5f}, {longitude:.5f}'
        if not label:
            return '-'
        if latitude is None or longitude is None:
            return label
        return format_html(
            '{}<br><a href="{}" target="_blank" rel="noopener noreferrer">Open map</a>',
            label,
            self._map_url(latitude, longitude),
        )

    def _map_link(self, latitude, longitude):
        if latitude is None or longitude is None:
            return '-'
        return format_html(
            '<a href="{}" target="_blank" rel="noopener noreferrer">Open map</a>',
            self._map_url(latitude, longitude),
        )

    def _map_url(self, latitude, longitude):
        lat = float(latitude)
        lon = float(longitude)
        return f'https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=12/{lat:.6f}/{lon:.6f}'

    def _security_status(self, is_anonymous, is_proxy, is_vpn, is_tor, is_hosting):
        values = {
            'Anonymous': is_anonymous,
            'Proxy': is_proxy,
            'VPN': is_vpn,
            'Tor': is_tor,
            'Hosting': is_hosting,
        }
        if all(value is None for value in values.values()):
            return '-'

        positives = [label for label, value in values.items() if value is True]
        if positives:
            return ', '.join(positives)

        if all(value is False for value in values.values()):
            return 'Direct'

        return 'Unknown'


@admin.register(PendingEmailSignup)
class PendingEmailSignupAdmin(admin.ModelAdmin):
    """Admin review surface for email-verification signup funnel."""

    change_list_template = 'admin/users/pendingemailsignup/change_list.html'
    list_display = [
        'email',
        'full_name',
        'ip_address',
        'accepted_at',
        'expires_status',
        'bot_status',
        'bot_signal_count',
        'reviewed_at',
    ]
    list_filter = [
        'is_bot_suspected',
        PendingEmailSignupStateFilter,
        'created_at',
        'accepted_at',
        'reviewed_at',
    ]
    search_fields = ['email', 'first_name', 'middle_name', 'last_name', 'ip_address', 'user_agent']
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
    list_per_page = 100
    exclude = ['password_hash']
    readonly_fields = [
        'created_at',
        'accepted_at',
        'expires_at',
        'ip_address',
        'user_agent',
        'bot_signals_pretty',
        'reviewed_at',
    ]
    actions = [
        'mark_selected_as_bot_like',
        'mark_selected_with_heuristics',
        'clear_bot_like_mark',
        'delete_selected_bot_like',
    ]

    fieldsets = (
        ('Pending Signup', {
            'fields': (
                'email',
                'first_name',
                'middle_name',
                'last_name',
                'phone',
                'address',
            )
        }),
        ('Submission', {
            'fields': (
                'created_at',
                'accepted_at',
                'expires_at',
                'ip_address',
                'user_agent',
            )
        }),
        ('Review', {
            'fields': (
                'is_bot_suspected',
                'reviewed_at',
                'bot_signals_pretty',
            )
        }),
    )

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context.update(self._funnel_context(request))
        return super().changelist_view(request, extra_context=extra_context)

    def save_model(self, request, obj, form, change):
        if change and 'is_bot_suspected' in getattr(form, 'changed_data', []):
            obj.reviewed_at = timezone.now()
            if obj.is_bot_suspected and not obj.bot_signals:
                obj.bot_signals = ['Manually marked in admin.']
            elif not obj.is_bot_suspected:
                obj.bot_signals = []
        super().save_model(request, obj, form, change)

    def has_add_permission(self, request):
        return False

    def full_name(self, obj):
        parts = [obj.first_name, obj.middle_name, obj.last_name]
        return ' '.join(part for part in parts if part) or '-'
    full_name.short_description = 'Name'

    def expires_status(self, obj):
        if obj.expires_at <= timezone.now():
            return format_html('<span style="color: #b91c1c; font-weight: 600;">Expired</span>')
        return format_html('<span style="color: #047857; font-weight: 600;">Active</span>')
    expires_status.short_description = 'State'

    def bot_status(self, obj):
        if obj.is_bot_suspected:
            return format_html('<span style="color: #b45309; font-weight: 600;">Suspected</span>')
        return format_html('<span style="color: #2563eb; font-weight: 600;">Clean</span>')
    bot_status.short_description = 'Bot Review'

    def bot_signal_count(self, obj):
        return len(obj.bot_signals or [])
    bot_signal_count.short_description = 'Signals'

    def bot_signals_pretty(self, obj):
        signals = obj.bot_signals or []
        if not signals:
            return 'No signals captured.'
        return format_html(
            '<ul style="margin: 0 0 0 1rem;">{}</ul>',
            format_html_join('', '<li>{}</li>', ((signal,) for signal in signals)),
        )
    bot_signals_pretty.short_description = 'Bot Signals'

    @admin.action(description='Mark selected pending signups as bot-like')
    def mark_selected_as_bot_like(self, request, queryset):
        reviewed_at = timezone.now()
        updated = 0
        for pending_signup in queryset:
            pending_signup.is_bot_suspected = True
            if not pending_signup.bot_signals:
                pending_signup.bot_signals = ['Manually marked in admin.']
            pending_signup.reviewed_at = reviewed_at
            pending_signup.save(update_fields=['is_bot_suspected', 'bot_signals', 'reviewed_at'])
            updated += 1
        self.message_user(request, f'Marked {updated} pending signups as bot-like.')

    @admin.action(description='Mark selected pending signups with heuristic bot review')
    def mark_selected_with_heuristics(self, request, queryset):
        selected = list(queryset)
        ip_addresses = {pending_signup.ip_address for pending_signup in selected if pending_signup.ip_address}
        ip_counts = {}
        if ip_addresses:
            ip_counts = {
                row['ip_address']: row['total']
                for row in PendingEmailSignup.objects.filter(ip_address__in=ip_addresses)
                .values('ip_address')
                .annotate(total=Count('id'))
            }

        reviewed_at = timezone.now()
        updated = 0
        for pending_signup in selected:
            signals, should_mark = self._bot_review(pending_signup, ip_counts)
            if not should_mark:
                continue
            pending_signup.is_bot_suspected = True
            pending_signup.bot_signals = signals
            pending_signup.reviewed_at = reviewed_at
            pending_signup.save(update_fields=['is_bot_suspected', 'bot_signals', 'reviewed_at'])
            updated += 1

        self.message_user(request, f'Heuristically marked {updated} pending signups as bot-like.')

    @admin.action(description='Clear bot-like mark from selected pending signups')
    def clear_bot_like_mark(self, request, queryset):
        reviewed_at = timezone.now()
        updated = 0
        for pending_signup in queryset:
            pending_signup.is_bot_suspected = False
            pending_signup.bot_signals = []
            pending_signup.reviewed_at = reviewed_at
            pending_signup.save(update_fields=['is_bot_suspected', 'bot_signals', 'reviewed_at'])
            updated += 1
        self.message_user(request, f'Cleared bot-like marks from {updated} pending signups.')

    @admin.action(description='Delete selected bot-like pending signups')
    def delete_selected_bot_like(self, request, queryset):
        bot_like_queryset = queryset.filter(is_bot_suspected=True)
        deleted_count = bot_like_queryset.count()
        bot_like_queryset.delete()
        self.message_user(request, f'Deleted {deleted_count} bot-like pending signups.')

    def _bot_review(self, pending_signup, ip_counts):
        signals = []
        strong_signals = 0
        weak_signals = 0

        email_local_part = pending_signup.email.partition('@')[0]
        if _generated_email_local_part(email_local_part):
            signals.append('Email local-part looks auto-generated.')
            strong_signals += 1

        user_agent = (pending_signup.user_agent or '').strip()
        if not user_agent:
            signals.append('Missing user agent.')
            weak_signals += 1
        elif len(user_agent) < 20:
            signals.append('Very short user agent.')
            weak_signals += 1

        ip_count = ip_counts.get(pending_signup.ip_address or '', 0)
        if pending_signup.ip_address and ip_count >= 3:
            signals.append(f'IP address reused across {ip_count} pending signups.')
            strong_signals += 1

        should_mark = strong_signals >= 2 or (strong_signals >= 1 and weak_signals >= 1)
        return signals, should_mark

    def _funnel_context(self, request):
        from scans.models import AuditLog

        period_key = request.GET.get('funnel_period', '7d')
        period_label, delta = _period_config(period_key)
        now = timezone.now()
        since = now - delta if delta else None

        register_visits = AuditLog.objects.filter(
            event_type='http.get',
            description__startswith='GET /register ->',
        )
        signup_posts = AuditLog.objects.filter(
            event_type='http.post',
            description__startswith='POST /api/auth/signup/ ->',
        )
        pending_signups = PendingEmailSignup.objects.all()
        verified_users = User.objects.filter(is_verified=True, is_staff=False, is_superuser=False)

        if since is not None:
            register_visits = register_visits.filter(created_at__gte=since)
            signup_posts = signup_posts.filter(created_at__gte=since)
            pending_signups = pending_signups.filter(created_at__gte=since)
            verified_users = verified_users.filter(created_at__gte=since)

        clean_pending_count = pending_signups.filter(is_bot_suspected=False).count()
        bot_pending_count = pending_signups.filter(is_bot_suspected=True).count()
        active_clean_pending = PendingEmailSignup.objects.filter(
            is_bot_suspected=False,
            expires_at__gt=now,
        ).count()

        register_visit_count = register_visits.count()
        signup_post_count = signup_posts.count()
        verified_user_count = verified_users.count()

        metrics = [
            {
                'label': 'Register Visits',
                'value': register_visit_count,
                'detail': 'Frontend GET /register hits captured by audit logs.',
            },
            {
                'label': 'Signup POST',
                'value': signup_post_count,
                'detail': f'Visit to signup rate: {_format_rate(signup_post_count, register_visit_count)}.',
            },
            {
                'label': 'Pending Email Signup',
                'value': clean_pending_count,
                'detail': (
                    f'Excluded bot-like rows: {bot_pending_count}. '
                    f'Active clean backlog now: {active_clean_pending}.'
                ),
            },
            {
                'label': 'Verified User',
                'value': verified_user_count,
                'detail': f'Pending to verified rate: {_format_rate(verified_user_count, clean_pending_count)}.',
            },
        ]

        period_options = [
            {
                'label': label,
                'url': _query_string_with(request, funnel_period=key),
                'selected': key == period_key,
            }
            for key, label, _ in _FUNNEL_PERIODS
        ]

        return {
            'funnel_title': f'Signup Funnel ({period_label})',
            'funnel_period_options': period_options,
            'funnel_metrics': metrics,
            'funnel_note': 'Pending email signup metrics exclude rows marked as bot-like.',
        }


@admin.register(ScanAuditLog)
class ScanAuditLogAdmin(admin.ModelAdmin):
    """Scan audit log admin"""

    list_display = [
        'user',
        'action',
        'scan_type',
        'target',
        'ip_address',
        'vulnerabilities_found',
        'created_at',
    ]
    list_filter = ['action', 'scan_type', 'created_at', 'used_nuclei', 'used_custom_payloads']
    search_fields = ['user__email', 'target', 'ip_address']
    ordering = ['-created_at']
    readonly_fields = ['created_at']

    fieldsets = (
        (None, {'fields': ('scan', 'user', 'action', 'scan_type', 'target')}),
        ('Network info', {'fields': ('ip_address', 'user_agent', 'geo_country', 'geo_city')}),
        (
            'Results',
            {
                'fields': (
                    'vulnerabilities_found',
                    'severity_critical',
                    'severity_high',
                    'severity_medium',
                    'severity_low',
                    'duration_seconds',
                )
            },
        ),
        ('Dangerous tools', {'fields': ('used_nuclei', 'used_custom_payloads', 'used_brute_force')}),
        ('Metadata', {'fields': ('metadata', 'error_message', 'created_at')}),
    )


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    """Team admin"""

    list_display = ['name', 'owner', 'member_count', 'max_members', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'owner__email']
    ordering = ['-created_at']
    readonly_fields = ['invite_code', 'created_at', 'updated_at', 'member_count']

    fieldsets = (
        (None, {'fields': ('name', 'description', 'owner', 'max_members')}),
        ('Status', {'fields': ('is_active', 'invite_code')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )


@admin.register(TeamMember)
class TeamMemberAdmin(admin.ModelAdmin):
    """Team member admin"""

    list_display = ['user', 'team', 'role', 'is_active', 'joined_at']
    list_filter = ['role', 'is_active', 'joined_at']
    search_fields = ['user__email', 'team__name']
    ordering = ['-joined_at']
    readonly_fields = ['joined_at', 'updated_at']

    fieldsets = (
        (None, {'fields': ('team', 'user', 'role', 'invited_by')}),
        (
            'Permissions',
            {
                'fields': (
                    'can_create_scans',
                    'can_view_all_scans',
                    'can_delete_scans',
                    'can_manage_members',
                )
            },
        ),
        ('Status', {'fields': ('is_active',)}),
        ('Timestamps', {'fields': ('joined_at', 'updated_at')}),
    )


@admin.register(TeamInvitation)
class TeamInvitationAdmin(admin.ModelAdmin):
    """Team invitation admin"""

    list_display = ['email', 'team', 'invited_by', 'role', 'status', 'created_at', 'expires_at']
    list_filter = ['status', 'role', 'created_at']
    search_fields = ['email', 'team__name', 'invited_by__email']
    ordering = ['-created_at']
    readonly_fields = ['token', 'created_at', 'updated_at', 'accepted_at']

    fieldsets = (
        (None, {'fields': ('team', 'email', 'invited_by', 'role')}),
        ('Status', {'fields': ('status', 'token', 'expires_at')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at', 'accepted_at')}),
    )


@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    """Integration admin"""

    list_display = ['name', 'integration_type', 'user', 'team', 'status', 'total_triggers', 'last_triggered_at']
    list_filter = ['integration_type', 'status', 'is_active', 'created_at']
    search_fields = ['name', 'user__email', 'team__name']
    ordering = ['-created_at']
    readonly_fields = [
        'created_at',
        'updated_at',
        'last_triggered_at',
        'last_error_at',
        'total_triggers',
        'successful_triggers',
        'failed_triggers']

    fieldsets = (
        (None, {'fields': ('user', 'team', 'integration_type', 'name')}),
        ('Configuration', {'fields': ('config', 'events')}),
        ('Status', {'fields': ('status', 'is_active')}),
        ('Error tracking', {'fields': ('last_error', 'last_error_at', 'error_count')}),
        ('Statistics', {'fields': ('total_triggers', 'successful_triggers', 'failed_triggers', 'last_triggered_at')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )

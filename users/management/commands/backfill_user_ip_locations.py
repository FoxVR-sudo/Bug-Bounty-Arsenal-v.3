from __future__ import annotations

import ipaddress

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from users.location import lookup_geo_details_for_ip
from users.models import LegalAcceptance


class Command(BaseCommand):
    help = 'Backfill user registration and last-seen IP/location/security fields from signup/legal/audit history.'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Preview changes without writing to the database.')
        parser.add_argument('--limit', type=int, default=0, help='Maximum number of users to process (0 = all).')
        parser.add_argument('--user-id', type=int, help='Backfill a single user by numeric ID.')

    def handle(self, *args, **options):
        User = get_user_model()
        queryset = User.objects.order_by('date_joined')
        user_id = options.get('user_id')
        limit = int(options.get('limit') or 0)
        dry_run = bool(options.get('dry_run'))

        if user_id:
            queryset = queryset.filter(pk=user_id)
        if limit > 0:
            queryset = queryset[:limit]

        geo_cache: dict[str, dict[str, object]] = {}
        processed = 0
        updated = 0

        for user in queryset:
            processed += 1
            update_fields = self._build_update_fields(user, geo_cache)
            if not update_fields:
                continue

            updated += 1
            if dry_run:
                self.stdout.write(f'DRY-RUN user={user.pk} {user.email}: {update_fields}')
                continue

            User.objects.filter(pk=user.pk).update(**update_fields)
            self.stdout.write(f'UPDATED user={user.pk} {user.email}: {update_fields}')

        summary = f'Processed {processed} users; {updated} needed updates.'
        if dry_run:
            summary = f'{summary} No database writes performed.'
        self.stdout.write(self.style.SUCCESS(summary))

    def _build_update_fields(self, user, geo_cache):
        update_fields = {}

        signup_acceptance = (
            LegalAcceptance.objects.filter(user=user, event=LegalAcceptance.EVENT_SIGNUP)
            .exclude(ip_address__isnull=True)
            .order_by('accepted_at')
            .first()
        )
        latest_login_audit = (
            user.audit_logs.exclude(ip_address__isnull=True)
            .filter(event_type='auth.login')
            .order_by('-created_at')
            .first()
        )
        latest_audit = user.audit_logs.exclude(ip_address__isnull=True).order_by('-created_at').first()

        registration_ip = self._best_public_ip(
            user.registration_ip,
            getattr(signup_acceptance, 'ip_address', None),
            getattr(latest_login_audit, 'ip_address', None),
            getattr(latest_audit, 'ip_address', None),
        )
        last_seen_ip = self._best_public_ip(
            user.last_seen_ip,
            getattr(latest_login_audit, 'ip_address', None),
            getattr(latest_audit, 'ip_address', None),
            registration_ip,
        )

        if registration_ip and not self._is_public_ip(user.registration_ip):
            update_fields['registration_ip'] = registration_ip
        if last_seen_ip and not self._is_public_ip(user.last_seen_ip):
            update_fields['last_seen_ip'] = last_seen_ip

        self._fill_geo_fields(
            update_fields,
            ip=registration_ip,
            prefix='registration',
            current_values={
                'city': user.registration_city,
                'country': user.registration_country,
                'latitude': user.registration_latitude,
                'longitude': user.registration_longitude,
                'is_anonymous': user.registration_is_anonymous,
                'is_proxy': user.registration_is_proxy,
                'is_vpn': user.registration_is_vpn,
                'is_tor': user.registration_is_tor,
                'is_hosting': user.registration_is_hosting,
            },
            geo_cache=geo_cache,
        )
        self._fill_geo_fields(
            update_fields,
            ip=last_seen_ip,
            prefix='last_seen',
            current_values={
                'city': user.last_seen_city,
                'country': user.last_seen_country,
                'latitude': user.last_seen_latitude,
                'longitude': user.last_seen_longitude,
                'is_anonymous': user.last_seen_is_anonymous,
                'is_proxy': user.last_seen_is_proxy,
                'is_vpn': user.last_seen_is_vpn,
                'is_tor': user.last_seen_is_tor,
                'is_hosting': user.last_seen_is_hosting,
            },
            geo_cache=geo_cache,
        )

        return update_fields

    def _fill_geo_fields(
        self,
        update_fields,
        *,
        ip,
        prefix,
        current_values,
        geo_cache,
    ):
        normalized_ip = str(ip or '').strip()
        detail_keys = (
            'city',
            'country',
            'latitude',
            'longitude',
            'is_anonymous',
            'is_proxy',
            'is_vpn',
            'is_tor',
            'is_hosting',
        )

        if not normalized_ip or all(self._has_stored_value(current_values.get(key)) for key in detail_keys):
            return

        if normalized_ip not in geo_cache:
            geo_cache[normalized_ip] = lookup_geo_details_for_ip(normalized_ip)
        geo_details = geo_cache[normalized_ip]

        for key in detail_keys:
            if self._has_stored_value(current_values.get(key)):
                continue

            value = geo_details.get(key)
            if not self._has_stored_value(value):
                continue

            update_fields[f'{prefix}_{key}'] = value

    def _has_stored_value(self, value):
        return value is not None and value != ''

    def _best_public_ip(self, *candidates):
        for candidate in candidates:
            if self._is_public_ip(candidate):
                return str(candidate).strip()
        return None

    def _is_public_ip(self, value):
        candidate = str(value or '').strip()
        if not candidate:
            return False

        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return False

        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

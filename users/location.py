"""Helpers for resolving and persisting user IP/location data."""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
from urllib.parse import urlencode

from django.conf import settings


logger = logging.getLogger(__name__)

_SECURITY_FIELDS = (
    ('is_anonymous', 'anonymous'),
    ('is_proxy', 'proxy'),
    ('is_vpn', 'vpn'),
    ('is_tor', 'tor'),
    ('is_hosting', 'hosting'),
)


def _fetch_geo_payload(url: str) -> dict:
    request = urllib.request.Request(url, headers={'User-Agent': 'BugBountyArsenal/1.0'})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode())


def _to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if normalized in ('1', 'true', 'yes', 'on'):
        return True
    if normalized in ('0', 'false', 'no', 'off'):
        return False
    return None


def _empty_geo_details() -> dict[str, object]:
    details = {
        'city': '',
        'country': '',
        'latitude': None,
        'longitude': None,
    }
    for field_name, _ in _SECURITY_FIELDS:
        details[field_name] = None
    return details


def _has_lookup_data(details: dict[str, object]) -> bool:
    return any(value is not None and value != '' for value in details.values())


def _ipwhois_url(ip: str, *, include_security: bool = False) -> str:
    if not include_security:
        return f'https://ipwho.is/{ip}'
    return f'https://ipwho.is/{ip}?{urlencode({"security": "1"})}'


def _parse_ipapi_payload(payload: dict, empty: dict[str, object]) -> dict[str, object]:
    if payload.get('error'):
        return empty

    details = empty.copy()
    details.update(
        {
            'city': str(payload.get('city') or '').strip(),
            'country': str(payload.get('country_code') or '').strip().upper(),
            'latitude': _to_float(payload.get('latitude')),
            'longitude': _to_float(payload.get('longitude')),
        }
    )
    return details


def _parse_ipwhois_payload(payload: dict, empty: dict[str, object]) -> dict[str, object]:
    if not payload.get('success', True):
        return empty

    details = empty.copy()
    details.update(
        {
            'city': str(payload.get('city') or '').strip(),
            'country': str(payload.get('country_code') or '').strip().upper(),
            'latitude': _to_float(payload.get('latitude')),
            'longitude': _to_float(payload.get('longitude')),
        }
    )

    security = payload.get('security') or {}
    for field_name, payload_key in _SECURITY_FIELDS:
        details[field_name] = _to_bool(security.get(payload_key))

    return details


def lookup_geo_details_for_ip(ip: str | None) -> dict[str, object]:
    normalized_ip = str(ip or '').strip()
    empty = _empty_geo_details()
    if not normalized_ip or normalized_ip in ('127.0.0.1', '::1'):
        return empty

    ipwhois_security_enabled = bool(getattr(settings, 'IPWHOIS_SECURITY_ENABLED', False))
    providers = []
    if ipwhois_security_enabled:
        providers.append((_ipwhois_url(normalized_ip, include_security=True), _parse_ipwhois_payload))

    providers.extend(
        [
            (f'https://ipapi.co/{normalized_ip}/json/', _parse_ipapi_payload),
            (_ipwhois_url(normalized_ip), _parse_ipwhois_payload),
        ]
    )

    for url, parser in providers:
        try:
            details = parser(_fetch_geo_payload(url), empty)
            if _has_lookup_data(details):
                return details
        except Exception:
            logger.debug('Failed geo lookup for IP %s via %s', normalized_ip, url, exc_info=True)

    return empty


def lookup_geo_for_ip(ip: str | None) -> tuple[str, str]:
    details = lookup_geo_details_for_ip(ip)
    return str(details.get('city') or ''), str(details.get('country') or '')


def update_user_location_async(user_id: int, ip: str | None, *, include_registration: bool = False) -> None:
    normalized_ip = str(ip or '').strip()

    def _run() -> None:
        update_fields = {}
        if normalized_ip:
            update_fields['last_seen_ip'] = normalized_ip
            if include_registration:
                update_fields['registration_ip'] = normalized_ip

        details = lookup_geo_details_for_ip(normalized_ip)
        city = str(details.get('city') or '')
        country = str(details.get('country') or '')
        latitude = details.get('latitude')
        longitude = details.get('longitude')

        if city:
            update_fields['last_seen_city'] = city
            if include_registration:
                update_fields['registration_city'] = city

        if country:
            update_fields['last_seen_country'] = country
            if include_registration:
                update_fields['registration_country'] = country

        if latitude is not None:
            update_fields['last_seen_latitude'] = latitude
            if include_registration:
                update_fields['registration_latitude'] = latitude

        if longitude is not None:
            update_fields['last_seen_longitude'] = longitude
            if include_registration:
                update_fields['registration_longitude'] = longitude

        for detail_key, suffix in _SECURITY_FIELDS:
            value = details.get(detail_key)
            if value is None:
                continue

            update_fields[f'last_seen_{detail_key}'] = value
            if include_registration:
                update_fields[f'registration_{detail_key}'] = value

        if not update_fields:
            return

        try:
            from users.models import User

            User.objects.filter(pk=user_id).update(**update_fields)
        except Exception:
            logger.exception('Failed to persist IP/location for user %s', user_id)

    threading.Thread(target=_run, daemon=True).start()

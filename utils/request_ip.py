import ipaddress
import os
from typing import Optional


def _is_trusted_proxy(remote_addr: str, trusted_raw: str) -> bool:
    trusted_entries = [entry.strip() for entry in trusted_raw.split(',') if entry.strip()]
    if not trusted_entries:
        try:
            ip = ipaddress.ip_address(remote_addr)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback

    try:
        ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False

    for entry in trusted_entries:
        try:
            if '/' in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue

    return False


def _forwarded_client_ip(request) -> Optional[str]:
    for header_name in ('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'):
        value = str(request.META.get(header_name, '') or '').strip()
        if not value:
            continue

        if header_name == 'HTTP_X_FORWARDED_FOR':
            value = value.split(',')[0].strip()

        if value:
            return value

    return None


def get_client_ip(request) -> Optional[str]:
    """Return a client IP for logging/throttling.

    Security note: never trust client-supplied X-Forwarded-For unless the
    request comes from a trusted proxy. Otherwise an attacker can spoof IPs and
    bypass rate limits.

    Configure trusted proxies via env:
      TRUSTED_PROXY_IPS="127.0.0.1,10.0.0.1"
    """

    if request is None:
        return None

    remote_addr = request.META.get("REMOTE_ADDR")
    if not remote_addr:
        return None

    trusted_raw = os.getenv("TRUSTED_PROXY_IPS", "")

    # Honor proxy headers when the immediate peer is explicitly trusted, or
    # when the peer is a private/loopback address (common in Docker/nginx setups).
    if _is_trusted_proxy(remote_addr, trusted_raw):
        forwarded_ip = _forwarded_client_ip(request)
        if forwarded_ip:
            return forwarded_ip

    return remote_addr

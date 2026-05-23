"""
Domain Ownership Verification API

Endpoints:
  POST   /api/domain-verify/initiate/   – request a token for a domain
  POST   /api/domain-verify/check/      – run HTTP / DNS verification
  GET    /api/domain-verify/            – list user's verified domains
  DELETE /api/domain-verify/<domain>/   – revoke a verified domain
"""
import logging
import re
import secrets

import requests as http_requests
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from scans.models import DomainVerification

logger = logging.getLogger(__name__)

# Token TTL for pending verifications (seconds).
# Expired pending entries are re-issued automatically.
_PENDING_TTL_SECONDS = 86_400  # 24 h

# Timeout for outbound HTTP probes (seconds).
_HTTP_PROBE_TIMEOUT = 10

_VALID_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_http(domain: str, token: str) -> bool:
    """Try the HTTP well-known verification method."""
    url = f"https://{domain}/.well-known/bugbounty-arsenal-verify.txt"
    try:
        resp = http_requests.get(
            url,
            timeout=_HTTP_PROBE_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )
        return resp.status_code == 200 and token in resp.text
    except Exception as exc:
        logger.debug("HTTP well-known check failed for %s: %s", domain, exc)
        return False


def _check_dns(domain: str, token: str) -> bool:
    """Try the DNS TXT record verification method (requires dnspython)."""
    expected = f"bugbounty-arsenal-verify={token}"
    try:
        import dns.resolver  # type: ignore[import]
        answers = dns.resolver.resolve(domain, "TXT", lifetime=10)
        for rdata in answers:
            for string in rdata.strings:
                decoded = string.decode("utf-8", errors="ignore") if isinstance(string, bytes) else string
                if decoded == expected:
                    return True
    except ImportError:
        logger.debug("dnspython not installed; DNS check skipped")
    except Exception as exc:
        logger.debug("DNS TXT check failed for %s: %s", domain, exc)
    return False


def _normalise_domain(raw: str) -> str:
    """Strip scheme/path/port and lower-case the input."""
    raw = raw.strip().lower()
    if raw.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        raw = urlparse(raw).hostname or raw
    raw = raw.split("/")[0].split(":")[0].lstrip("www.")
    return raw


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_domain_verification(request):
    """
    POST /api/domain-verify/initiate/
    Body: { "domain": "example.com" }

    Creates (or refreshes) a pending DomainVerification record and returns
    the token + instructions for both verification methods.
    """
    raw_domain = request.data.get("domain", "").strip()
    domain = _normalise_domain(raw_domain)

    if not domain or not _VALID_DOMAIN_RE.match(domain):
        return Response(
            {"error": "Invalid domain. Provide an apex domain like 'example.com'."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Prevent trivially unverifiable targets
    if domain in ("localhost", "127.0.0.1", "0.0.0.0"):
        return Response(
            {"error": "Localhost / loopback addresses cannot be verified."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Already verified — nothing to do
    existing = DomainVerification.objects.filter(user=request.user, domain=domain).first()
    if existing and existing.status == DomainVerification.STATUS_VERIFIED:
        return Response({
            "domain": domain,
            "status": "verified",
            "verified_at": existing.verified_at,
            "message": "Domain is already verified.",
        })

    # Create or refresh a pending record
    token = secrets.token_urlsafe(32)
    if existing:
        existing.token = token
        existing.status = DomainVerification.STATUS_PENDING
        existing.last_check_error = ""
        existing.verified_at = None
        existing.save(update_fields=["token", "status", "last_check_error", "verified_at"])
        record = existing
    else:
        record = DomainVerification.objects.create(
            user=request.user,
            domain=domain,
            token=token,
        )

    return Response({
        "domain": domain,
        "status": "pending",
        "token": record.token,
        "instructions": {
            "http": {
                "method": "HTTP file",
                "description": (
                    f"Create the file at: https://{domain}/.well-known/bugbounty-arsenal-verify.txt"
                    f"\nFile contents must contain exactly: {record.token}"
                ),
                "url": record.get_http_challenge_url(),
                "file_content": record.token,
            },
            "dns": {
                "method": "DNS TXT record",
                "description": (
                    f"Add a TXT record to your DNS zone for '{domain}' with the value:\n"
                    f"  {record.get_dns_txt_value()}"
                ),
                "record_type": "TXT",
                "record_name": domain,
                "record_value": record.get_dns_txt_value(),
            },
        },
    }, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def check_domain_verification(request):
    """
    POST /api/domain-verify/check/
    Body: { "domain": "example.com" }

    Probes the domain via HTTP well-known first, then DNS TXT.
    Returns { verified: true/false, method: "http"|"dns"|null, error: "..." }
    """
    raw_domain = request.data.get("domain", "").strip()
    domain = _normalise_domain(raw_domain)

    if not domain:
        return Response({"error": "Domain is required."}, status=status.HTTP_400_BAD_REQUEST)

    record = DomainVerification.objects.filter(user=request.user, domain=domain).first()
    if not record:
        return Response(
            {"error": "No pending verification found. Call /initiate/ first."},
            status=status.HTTP_404_NOT_FOUND,
        )

    if record.status == DomainVerification.STATUS_VERIFIED:
        return Response({"verified": True, "method": "already_verified", "domain": domain})

    token = record.token
    verified_via = None

    if _check_http(domain, token):
        verified_via = "http"
    elif _check_dns(domain, token):
        verified_via = "dns"

    if verified_via:
        record.status = DomainVerification.STATUS_VERIFIED
        record.verified_at = timezone.now()
        record.last_check_error = ""
        record.save(update_fields=["status", "verified_at", "last_check_error"])
        return Response({
            "verified": True,
            "method": verified_via,
            "domain": domain,
            "verified_at": record.verified_at,
        })

    error_msg = (
        "Verification failed. Make sure the HTTP file or DNS TXT record is in place, "
        "then try again. DNS changes may take up to 30 minutes to propagate."
    )
    record.last_check_error = error_msg
    record.save(update_fields=["last_check_error"])
    return Response({
        "verified": False,
        "domain": domain,
        "error": error_msg,
        "http_url": record.get_http_challenge_url(),
        "dns_txt": record.get_dns_txt_value(),
    }, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_verified_domains(request):
    """
    GET /api/domain-verify/
    Returns all DomainVerification records for the current user.
    """
    records = DomainVerification.objects.filter(user=request.user)
    data = []
    for r in records:
        data.append({
            "domain": r.domain,
            "status": r.status,
            "verified_at": r.verified_at,
            "created_at": r.created_at,
            "http_challenge_url": r.get_http_challenge_url() if r.status == DomainVerification.STATUS_PENDING else None,
            "dns_txt_value": r.get_dns_txt_value() if r.status == DomainVerification.STATUS_PENDING else None,
        })
    return Response(data)


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_domain_verification(request, domain: str):
    """
    DELETE /api/domain-verify/<domain>/
    Removes the verification record for the given domain.
    """
    domain = _normalise_domain(domain)
    deleted, _ = DomainVerification.objects.filter(user=request.user, domain=domain).delete()
    if not deleted:
        return Response({"error": "Domain not found."}, status=status.HTTP_404_NOT_FOUND)
    return Response(status=status.HTTP_204_NO_CONTENT)

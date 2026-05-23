# detectors/cors_detector.py
"""
CORS Misconfiguration Detector - Common security issue

Tests for:
- Wildcard origin reflection (Access-Control-Allow-Origin: *)
- Null origin bypass
- Arbitrary origin reflection
- Credential leakage (ACAO + credentials: true)
- Subdomain trust issues
- Pre-flight bypass

Expected Bounty Value: $200-$2,000 per finding
Common in: APIs, SaaS platforms, microservices
Easy to exploit: Just need to send Origin header
"""
import logging
from urllib.parse import urlparse
from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)


@register_active
async def cors_detector(session, url, context):
    """
    Detect CORS misconfigurations.

    Tests multiple Origin values and checks if server reflects them.
    """
    findings = []

    try:
        per_host_rate = context.get("per_host_rate", None)

        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # Test origins
        test_origins = [
            "https://evil.com",  # Arbitrary domain
            "null",  # Null origin (file://, sandboxed iframe)
            f"https://evil.{host}",  # Subdomain of target (if trust misconfigured)
            f"https://{host}.evil.com",  # Subdomain containing target domain
            "https://attacker.com",
        ]

        logger.info(f"🔍 Testing CORS misconfigurations on {url}")

        for origin in test_origins[:3]:  # Test first 3 origins
            await await_host_token(host, per_host_rate)

            try:
                headers = {
                    "Origin": origin,
                    "Accept": "application/json",
                }

                async with session.get(url, headers=headers, timeout=10) as resp:
                    status = resp.status
                    resp_headers = dict(resp.headers)

                    # Check Access-Control-Allow-Origin (ACAO)
                    acao = resp_headers.get("Access-Control-Allow-Origin", "")
                    acac = resp_headers.get("Access-Control-Allow-Credentials", "")

                    # Critical finding: Origin reflected + credentials allowed
                    if acao == origin and acac.lower() == "true":
                        findings.append({
                            "type": "CORS Misconfiguration - Credential Leakage",
                            "severity": "high",
                            "evidence": f"Server reflects arbitrary origin ({origin}) with credentials enabled",
                            "how_found": f"Sent Origin: {origin}, received ACAO: {acao} with credentials: true",
                            "evidence_url": url,
                            "evidence_status": status,
                            "origin_sent": origin,
                            "acao_received": acao,
                            "credentials_allowed": acac,
                            "impact": "HIGH: Attacker can make authenticated requests from malicious site and steal sensitive data (cookies, session tokens). Leads to account takeover.",
                            "remediation": "Use whitelist of allowed origins. Never reflect arbitrary origins with credentials: true",
                            "cve_reference": "CWE-346: Origin Validation Error",
                            "repro_command": f"curl -H 'Origin: {origin}' '{url}'",
                            "exploit_poc": f"fetch('{url}', {{credentials: 'include', headers: {{'Origin': '{origin}'}}}})",
                        })

                        logger.warning(f"🔥 HIGH: CORS credential leakage on {url} (origin: {origin})")

                    # Medium finding: Origin reflected (no credentials)
                    elif acao == origin:
                        findings.append({
                            "type": "CORS Misconfiguration - Origin Reflection",
                            "severity": "medium",
                            "evidence": f"Server reflects arbitrary origin: {origin}",
                            "how_found": f"Sent Origin: {origin}, received ACAO: {acao}",
                            "evidence_url": url,
                            "evidence_status": status,
                            "origin_sent": origin,
                            "acao_received": acao,
                            "impact": "MEDIUM: Attacker can make requests from malicious site. Can bypass CORS for non-authenticated requests.",
                            "remediation": "Use whitelist of allowed origins. Don't reflect arbitrary origins.",
                            "cve_reference": "CWE-346: Origin Validation Error",
                        })

                        logger.info(f"ℹ️  MEDIUM: CORS origin reflection on {url} (origin: {origin})")

                    # Check for wildcard with credentials (invalid but some browsers allow)
                    elif acao == "*" and acac.lower() == "true":
                        findings.append({
                            "type": "CORS Misconfiguration - Wildcard with Credentials",
                            "severity": "medium",
                            "evidence": "Server uses ACAO: * with credentials: true (invalid config)",
                            "how_found": "ACAO: * with Access-Control-Allow-Credentials: true",
                            "evidence_url": url,
                            "evidence_status": status,
                            "impact": "Invalid CORS configuration. Some browsers may allow this, leading to credential leakage.",
                            "remediation": "Don't use wildcard (*) with credentials: true. Use specific origins.",
                        })

                    # Low severity: Just wildcard (common, but no credential leak)
                    elif acao == "*":
                        findings.append({
                            "type": "CORS Allows All Origins",
                            "severity": "low",
                            "evidence": "Server allows all origins (ACAO: *)",
                            "how_found": "Access-Control-Allow-Origin: *",
                            "evidence_url": url,
                            "evidence_status": status,
                            "impact": "LOW: All origins allowed. Public API - acceptable if no sensitive data exposed.",
                            "remediation": "If API contains sensitive data, use whitelist instead of wildcard.",
                        })

            except Exception as e:
                logger.debug(f"CORS test failed for origin {origin}: {e}")

        # Test pre-flight bypass (OPTIONS request)
        logger.info(f"🔍 Testing CORS pre-flight on {url}")
        await await_host_token(host, per_host_rate)

        try:
            headers = {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header",
            }

            async with session.options(url, headers=headers, timeout=10) as resp:
                status = resp.status
                resp_headers = dict(resp.headers)

                acao = resp_headers.get("Access-Control-Allow-Origin", "")
                acam = resp_headers.get("Access-Control-Allow-Methods", "")
                resp_headers.get("Access-Control-Allow-Headers", "")

                # Check if dangerous methods are allowed
                dangerous_methods = ["PUT", "DELETE", "PATCH"]
                allowed_methods = [m.strip().upper() for m in acam.split(",") if m]

                if any(method in allowed_methods for method in dangerous_methods):
                    findings.append({
                        "type": "CORS Allows Dangerous Methods",
                        "severity": "medium",
                        "evidence": f"Pre-flight allows dangerous methods: {acam}",
                        "how_found": f"OPTIONS request returned ACAM: {acam}",
                        "evidence_url": url,
                        "evidence_status": status,
                        "allowed_methods": acam,
                        "impact": "CORS allows PUT/DELETE/PATCH from cross-origin. Can modify or delete resources.",
                        "remediation": "Restrict allowed methods to GET, POST only. Require authentication for dangerous methods.",
                    })

                    logger.info(f"ℹ️  MEDIUM: CORS allows dangerous methods on {url}")

        except Exception as e:
            logger.debug(f"Pre-flight test failed: {e}")

    except Exception as e:
        logger.exception(f"cors_detector error for {url}: {e}")

    return findings

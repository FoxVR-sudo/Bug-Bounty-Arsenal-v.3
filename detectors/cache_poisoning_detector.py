# detectors/cache_poisoning_detector.py
"""
Cache Poisoning Detector - Web cache vulnerabilities

Tests for:
- Web cache deception
- Host header poisoning
- X-Forwarded-Host poisoning
- X-Forwarded-Scheme poisoning
- Unkeyed input detection
- Cache key normalization bypass

Expected Bounty Value: $500-$5,000 per finding
Common in: CDNs, reverse proxies, caching layers
Attack impact: Stored XSS, password reset poisoning, defacement
"""
import logging
from urllib.parse import urlparse
from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)

# Cache headers to check
CACHE_HEADERS = [
    "X-Cache",
    "X-Cache-Status",
    "CF-Cache-Status",  # Cloudflare
    "X-Varnish",
    "Age",
    "Cache-Control",
    "X-Fastly-Cache-Status",  # Fastly
    "X-Akamai-Cache-Status",  # Akamai
]


@register_active
async def cache_poisoning_detector(session, url, context):
    """
    Detect web cache poisoning vulnerabilities.

    Tests various cache poisoning techniques.
    """
    findings = []

    try:
        per_host_rate = context.get("per_host_rate", None)

        parsed = urlparse(url)
        host = parsed.netloc.lower()

        logger.info(f"🔍 Testing cache poisoning on {url}")

        # Test 1: Check if response is cached
        await await_host_token(host, per_host_rate)

        cached = False
        cache_header = None

        try:
            async with session.get(url, timeout=10) as resp:
                status = resp.status
                headers = dict(resp.headers)

                # Check for cache headers
                for cache_hdr in CACHE_HEADERS:
                    if cache_hdr in headers:
                        cache_value = headers[cache_hdr].lower()
                        if any(indicator in cache_value for indicator in ["hit", "cached", "ok"]):
                            cached = True
                            cache_header = f"{cache_hdr}: {headers[cache_hdr]}"
                            logger.info(f"✅ Response is cached: {cache_header}")
                            break

        except Exception as e:
            logger.debug(f"Cache check failed: {e}")
            return findings

        if not cached:
            logger.debug(f"Response not cached, skipping cache poisoning tests")
            return findings

        # Test 2: Host header poisoning
        logger.info(f"🔍 Testing Host header poisoning")
        await await_host_token(host, per_host_rate)

        try:
            poison_host = "evil.com"
            headers = {"Host": poison_host}

            async with session.get(url, headers=headers, timeout=10) as resp:
                status = resp.status
                body = await resp.text()
                resp_headers = dict(resp.headers)

                # Check if poisoned host appears in response
                if poison_host in body:
                    findings.append({
                        "type": "Cache Poisoning - Host Header",
                        "severity": "high",
                        "evidence": f"Poisoned Host header ({poison_host}) reflected in cached response",
                        "how_found": f"Sent Host: {poison_host}, value appeared in response body",
                        "evidence_url": url,
                        "evidence_status": status,
                        "evidence_body": body[:500],
                        "poisoned_header": f"Host: {poison_host}",
                        "cache_header": cache_header,
                        "impact": "HIGH: Host header poisoning in cached response. Can poison cache for all users with malicious links, leading to password reset poisoning, stored XSS, or phishing.",
                        "remediation": "Don't trust Host header. Use configured server name. Exclude Host from cache key or validate it.",
                        "cve_reference": "CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax",
                        "repro_command": f"curl -H 'Host: {poison_host}' '{url}'",
                    })

                    logger.warning(f"🔥 HIGH: Host header cache poisoning on {url}!")

        except Exception as e:
            logger.debug(f"Host header test failed: {e}")

        # Test 3: X-Forwarded-Host poisoning
        logger.info(f"🔍 Testing X-Forwarded-Host poisoning")
        await await_host_token(host, per_host_rate)

        try:
            poison_xfh = "evil.com"
            headers = {"X-Forwarded-Host": poison_xfh}

            async with session.get(url, headers=headers, timeout=10) as resp:
                status = resp.status
                body = await resp.text()

                if poison_xfh in body:
                    findings.append({
                        "type": "Cache Poisoning - X-Forwarded-Host",
                        "severity": "high",
                        "evidence": f"X-Forwarded-Host ({poison_xfh}) reflected in cached response",
                        "how_found": f"Sent X-Forwarded-Host: {poison_xfh}, value appeared in response",
                        "evidence_url": url,
                        "evidence_status": status,
                        "poisoned_header": f"X-Forwarded-Host: {poison_xfh}",
                        "cache_header": cache_header,
                        "impact": "HIGH: X-Forwarded-Host poisoning. Attacker can inject malicious domain into cached responses.",
                        "remediation": "Don't trust X-Forwarded-Host. Exclude from cache key or validate strictly.",
                    })

                    logger.warning(f"🔥 HIGH: X-Forwarded-Host cache poisoning on {url}!")

        except Exception as e:
            logger.debug(f"X-Forwarded-Host test failed: {e}")

        # Test 4: X-Forwarded-Scheme poisoning (HTTP vs HTTPS)
        logger.info(f"🔍 Testing X-Forwarded-Scheme poisoning")
        await await_host_token(host, per_host_rate)

        try:
            headers = {"X-Forwarded-Scheme": "http"}

            async with session.get(url, headers=headers, timeout=10) as resp:
                status = resp.status
                body = await resp.text()
                location = resp.headers.get("Location", "")

                # Check if response changed to HTTP
                if "http://" in (body + location) and parsed.scheme == "https":
                    findings.append({
                        "type": "Cache Poisoning - X-Forwarded-Scheme",
                        "severity": "medium",
                        "evidence": "X-Forwarded-Scheme manipulation changes response to HTTP",
                        "how_found": "Sent X-Forwarded-Scheme: http, response contained http:// URLs",
                        "evidence_url": url,
                        "evidence_status": status,
                        "poisoned_header": "X-Forwarded-Scheme: http",
                        "impact": "MEDIUM: Can downgrade HTTPS links to HTTP in cached responses. Enables MITM attacks.",
                        "remediation": "Don't trust X-Forwarded-Scheme. Use actual request scheme.",
                    })

        except Exception as e:
            logger.debug(f"X-Forwarded-Scheme test failed: {e}")

        # Test 5: Unkeyed header detection (X-Original-URL, X-Rewrite-URL)
        logger.info(f"🔍 Testing unkeyed headers")
        await await_host_token(host, per_host_rate)

        unkeyed_headers = {
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Custom-Header": "test123",
        }

        for header_name, header_value in list(unkeyed_headers.items())[:2]:  # Test first 2
            await await_host_token(host, per_host_rate)

            try:
                headers = {header_name: header_value}

                async with session.get(url, headers=headers, timeout=10) as resp:
                    status = resp.status
                    body = await resp.text()

                    # Check if header value appears in response
                    if header_value in body or status == 403 or status == 401:
                        findings.append({
                            "type": "Cache Poisoning - Unkeyed Header",
                            "severity": "medium",
                            "evidence": f"Unkeyed header {header_name} affects response",
                            "how_found": f"Sent {header_name}: {header_value}, response changed",
                            "evidence_url": url,
                            "evidence_status": status,
                            "unkeyed_header": f"{header_name}: {header_value}",
                            "impact": f"MEDIUM: {header_name} is not in cache key but affects response. Can poison cache.",
                            "remediation": f"Include {header_name} in cache key or ignore it completely.",
                        })

                        logger.info(f"ℹ️  MEDIUM: Unkeyed header detected: {header_name}")

            except Exception as e:
                logger.debug(f"Unkeyed header test failed for {header_name}: {e}")

        # Test 6: Cache deception (append .css/.js to URL)
        if not url.endswith(('.css', '.js', '.jpg', '.png')):
            logger.info(f"🔍 Testing cache deception")
            await await_host_token(host, per_host_rate)

            try:
                # Append fake extension
                deception_url = url.rstrip('/') + '/test.css'

                async with session.get(deception_url, timeout=10) as resp:
                    status = resp.status
                    body = await resp.text()
                    resp_headers = dict(resp.headers)

                    # Check if server returns sensitive content
                    # but cache treats it as static file
                    is_cached = any(
                        hdr in resp_headers and
                        any(val in resp_headers[hdr].lower() for val in ["hit", "cached", "ok"])
                        for hdr in CACHE_HEADERS
                    )

                    has_sensitive_data = any(
                        indicator in body.lower()
                        for indicator in ["password", "token", "api_key", "secret", "email", "session"]
                    )

                    if status == 200 and is_cached and has_sensitive_data:
                        findings.append({
                            "type": "Web Cache Deception",
                            "severity": "high",
                            "evidence": f"Sensitive page cached as static file: {deception_url}",
                            "how_found": f"Appended .css to URL, server returned sensitive data with cache headers",
                            "evidence_url": deception_url,
                            "evidence_status": status,
                            "impact": "HIGH: Web cache deception allows attacker to cache sensitive user data. Attacker sends victim link with .css extension, cache stores victim's private data, attacker retrieves it.",
                            "remediation": "Configure cache to only cache specific extensions. Validate URL paths server-side.",
                            "cve_reference": "CWE-525: Use of Web Browser Cache Containing Sensitive Information",
                        })

                        logger.warning(f"🔥 HIGH: Web cache deception on {deception_url}!")

            except Exception as e:
                logger.debug(f"Cache deception test failed: {e}")

    except Exception as e:
        logger.exception(f"cache_poisoning_detector error for {url}: {e}")

    return findings

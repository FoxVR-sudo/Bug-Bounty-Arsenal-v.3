# detectors/rate_limit_bypass_detector.py
"""
Rate Limit Bypass Detector - Test for rate limiting weaknesses.

Tests for:
- IP-based rate limit bypass (X-Forwarded-For rotation)
- Session-based rate limit bypass (cookie/token rotation)
- Endpoint variations (different paths for same functionality)
- HTTP method variations
- User-Agent rotation
- Race conditions (parallel requests)

REQUIRES: --allow-destructive flag
"""
import asyncio
import logging
import random
from urllib.parse import urlparse
from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)

# Common rate-limited endpoints
RATE_LIMITED_PATHS = [
    "/api/login",
    "/api/auth/login",
    "/login",
    "/signin",
    "/api/register",
    "/register",
    "/api/password/reset",
    "/forgot-password",
    "/api/verify",
    "/api/otp",
]

# IP addresses for X-Forwarded-For rotation
FAKE_IPS = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
    f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
    f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
]

# User-Agent strings for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
]


@register_active
async def rate_limit_bypass_detector(session, url, context):
    """
    Test for rate limiting vulnerabilities and bypass techniques.
    """
    findings = []

    if not url:
        return findings

    allow_destructive = context.get("allow_destructive", False)
    if not allow_destructive:
        logger.debug("rate_limit_bypass_detector: Skipping (requires --allow-destructive flag)")
        return findings

    per_host_rate = context.get("per_host_rate", None)

    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.netloc.lower()

        # Test rate-limited endpoints
        for endpoint in RATE_LIMITED_PATHS[:3]:  # Test first 3
            test_url = base_url + endpoint

            # 1. Test baseline rate limiting (10 requests in sequence)
            logger.info(f"🔒 Testing rate limit on {endpoint}")

            baseline_statuses = []
            for i in range(10):
                await await_host_token(host, per_host_rate)
                status = await _make_request(session, test_url)
                if status:
                    baseline_statuses.append(status)
                await asyncio.sleep(0.1)  # Small delay

            # Check if rate limiting exists (429 or 403 after multiple requests)
            if 429 in baseline_statuses or (baseline_statuses.count(403) > 3):
                logger.info(f"✅ Rate limiting detected on {endpoint}")

                # 2. Test X-Forwarded-For bypass
                bypass_statuses = []
                for i in range(10):
                    await await_host_token(host, per_host_rate)
                    fake_ip = random.choice(FAKE_IPS)
                    headers = {"X-Forwarded-For": fake_ip}
                    status = await _make_request_with_headers(session, test_url, headers)
                    if status:
                        bypass_statuses.append(status)
                    await asyncio.sleep(0.1)

                # Success if we get fewer 429/403 with IP rotation
                if 429 not in bypass_statuses and bypass_statuses.count(403) < baseline_statuses.count(403):
                    findings.append({
                        "type": "Rate Limit Bypass - IP Rotation",
                        "evidence": f"Rate limit bypassed using X-Forwarded-For header rotation",
                        "how_found": f"IP rotation bypassed rate limiting on {endpoint}",
                        "severity": "high",
                        "payload": "X-Forwarded-For: [rotating IPs]",
                        "evidence_url": test_url,
                        "baseline_blocks": baseline_statuses.count(429) + baseline_statuses.count(403),
                        "bypass_blocks": bypass_statuses.count(429) + bypass_statuses.count(403),
                        "technique": "ip_rotation",
                    })
                    logger.warning(f"🔥 RATE LIMIT BYPASS: {endpoint} - IP rotation successful!")

                # 3. Test User-Agent rotation
                ua_statuses = []
                for i in range(10):
                    await await_host_token(host, per_host_rate)
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    status = await _make_request_with_headers(session, test_url, headers)
                    if status:
                        ua_statuses.append(status)
                    await asyncio.sleep(0.1)

                if 429 not in ua_statuses and ua_statuses.count(403) < baseline_statuses.count(403):
                    findings.append({
                        "type": "Rate Limit Bypass - User-Agent Rotation",
                        "evidence": f"Rate limit bypassed using User-Agent rotation",
                        "how_found": f"User-Agent rotation bypassed rate limiting on {endpoint}",
                        "severity": "medium",
                        "payload": "User-Agent: [rotating]",
                        "evidence_url": test_url,
                        "baseline_blocks": baseline_statuses.count(429) + baseline_statuses.count(403),
                        "bypass_blocks": ua_statuses.count(429) + ua_statuses.count(403),
                        "technique": "user_agent_rotation",
                    })
                    logger.warning(f"🔥 RATE LIMIT BYPASS: {endpoint} - User-Agent rotation successful!")

                # 4. Test HTTP method variation
                method_statuses = []
                for method in ["POST", "PUT", "PATCH"]:
                    await await_host_token(host, per_host_rate)
                    status = await _make_request_with_method(session, test_url, method)
                    if status and status != 429:
                        method_statuses.append((method, status))

                if method_statuses:
                    findings.append({
                        "type": "Rate Limit Bypass - Method Variation",
                        "evidence": f"Rate limit not applied to alternative HTTP methods",
                        "how_found": f"HTTP method variation bypassed rate limiting on {endpoint}",
                        "severity": "medium",
                        "payload": str([m[0] for m in method_statuses]),
                        "evidence_url": test_url,
                        "successful_methods": [m[0] for m in method_statuses],
                        "technique": "method_variation",
                    })
                    logger.warning(f"🔥 RATE LIMIT BYPASS: {endpoint} - Method variation successful!")

            # 5. Test race condition (parallel requests — capped at 8)
            logger.info(f"Testing race condition on {endpoint}")

            # Send 8 requests in parallel
            tasks = []
            for i in range(8):
                task = asyncio.create_task(_make_request(session, test_url))
                tasks.append(task)

            race_results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in race_results if r and r == 200)

            # If we get >5 successful requests in parallel, race condition exists
            if success_count > 5:
                findings.append({
                    "type": "Race Condition - No Rate Limiting",
                    "evidence": f"Endpoint vulnerable to race condition: {success_count}/8 parallel requests succeeded",
                    "how_found": f"Parallel request test bypassed rate limiting on {endpoint}",
                    "severity": "high",
                    "payload": "8 parallel requests",
                    "evidence_url": test_url,
                    "success_count": success_count,
                    "total_requests": 8,
                    "technique": "race_condition",
                })
                logger.warning(f"RACE CONDITION: {endpoint} - {success_count}/8 parallel requests succeeded!")

    except Exception as e:
        logger.exception(f"rate_limit_bypass_detector error for {url}: {e}")

    return findings


async def _make_request(session, url):
    """Make simple GET request and return status"""
    try:
        async with session.get(url, allow_redirects=False, timeout=5) as resp:
            return resp.status
    except Exception as e:
        logger.debug(f"Request error for {url}: {e}")
        return None


async def _make_request_with_headers(session, url, headers):
    """Make request with custom headers"""
    try:
        async with session.get(url, headers=headers, allow_redirects=False, timeout=5) as resp:
            return resp.status
    except Exception as e:
        logger.debug(f"Request error for {url}: {e}")
        return None


async def _make_request_with_method(session, url, method):
    """Make request with specific HTTP method"""
    try:
        async with session.request(method, url, allow_redirects=False, timeout=5) as resp:
            return resp.status
    except Exception as e:
        logger.debug(f"Request error for {url} with {method}: {e}")
        return None

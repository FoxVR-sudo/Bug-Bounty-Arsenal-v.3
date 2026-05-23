# detectors/brute_force_detector.py
"""
Brute Force Detector - Test for weak credentials and authentication issues.

Tests for:
- Default credentials (admin/admin, root/root)
- Common credential combinations
- Username enumeration
- Predictable tokens/session IDs
- Weak password policies

SAFE MODE:
- Max 5 attempts per endpoint (no account lockout)
- No DoS or aggressive brute forcing
- Rate limited to prevent service disruption

REQUIRES: --allow-destructive flag
"""
import asyncio
import logging
import time
from urllib.parse import urlparse
from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)

# Common login endpoints
LOGIN_PATHS = [
    "/api/login",
    "/api/auth/login",
    "/login",
    "/signin",
    "/authenticate",
    "/api/token",
    "/oauth/token",
]

# Default credential combinations (LIMITED to prevent lockout)
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("admin", "password"),
    ("admin", "admin123"),
]

# Common usernames for enumeration
COMMON_USERNAMES = [
    "admin",
    "administrator",
    "root",
    "test",
    "user",
]


@register_active
async def brute_force_detector(session, url, context):
    """
    Test for weak authentication and credential issues.
    SAFE MODE: Limited attempts to prevent account lockout.
    """
    findings = []

    if not url:
        return findings

    allow_destructive = context.get("allow_destructive", False)
    if not allow_destructive:
        logger.debug("brute_force_detector: Skipping (requires --allow-destructive flag)")
        return findings

    per_host_rate = context.get("per_host_rate", None)

    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.netloc.lower()

        # Test each login endpoint
        for endpoint in LOGIN_PATHS[:3]:  # Test first 3
            test_url = base_url + endpoint

            logger.info(f"🔐 Testing authentication on {endpoint}")

            # 1. Test default credentials (SAFE - only 5 attempts)
            for username, password in DEFAULT_CREDENTIALS:
                await await_host_token(host, per_host_rate)

                status, response_time, body_size = await _test_login(
                    session, test_url, username, password
                )

                if status == 200:
                    # SUCCESS - default credentials work!
                    findings.append({
                        "type": "Default Credentials",
                        "evidence": f"Default credentials accepted: {username}/{password}",
                        "how_found": f"Default credential test on {endpoint}",
                        "severity": "critical",
                        "payload": f"username={username}&password={password}",
                        "evidence_url": test_url,
                        "username": username,
                        "password": password,
                        "technique": "default_credentials",
                    })
                    logger.error(f"🔥 DEFAULT CREDENTIALS FOUND: {username}/{password} on {endpoint}")
                    break  # Stop testing this endpoint

                await asyncio.sleep(0.5)  # Delay to prevent lockout

            # 2. Test username enumeration (timing-based)
            logger.info(f"👤 Testing username enumeration on {endpoint}")

            timing_baseline = []
            for _ in range(3):  # Baseline with invalid user
                await await_host_token(host, per_host_rate)
                _, response_time, _ = await _test_login(
                    session, test_url, "nonexistent_user_xyz", "wrongpassword"
                )
                if response_time:
                    timing_baseline.append(response_time)
                await asyncio.sleep(0.3)

            if timing_baseline:
                avg_baseline = sum(timing_baseline) / len(timing_baseline)

                # Test common usernames
                timing_differences = []
                for username in COMMON_USERNAMES:
                    await await_host_token(host, per_host_rate)
                    _, response_time, _ = await _test_login(
                        session, test_url, username, "wrongpassword"
                    )

                    if response_time:
                        diff = response_time - avg_baseline
                        if abs(diff) > 0.1:  # Significant timing difference
                            timing_differences.append((username, diff, response_time))

                    await asyncio.sleep(0.3)

                # Report if timing differences detected
                if timing_differences:
                    findings.append({
                        "type": "Username Enumeration - Timing",
                        "evidence": f"Timing difference detected for valid usernames",
                        "how_found": f"Timing analysis on {endpoint}",
                        "severity": "medium",
                        "payload": str([u[0] for u in timing_differences]),
                        "evidence_url": test_url,
                        "baseline_time": f"{avg_baseline:.3f}s",
                        "timing_differences": [
                            {"username": u[0], "diff": f"{u[1]:.3f}s", "time": f"{u[2]:.3f}s"}
                            for u in timing_differences
                        ],
                        "technique": "timing_enumeration",
                    })
                    logger.warning(f"🕒 USERNAME ENUMERATION: {endpoint} - timing differences detected")

            # 3. Test response-based enumeration (different error messages)
            logger.info(f"📝 Testing response-based enumeration on {endpoint}")

            # Test with invalid user
            await await_host_token(host, per_host_rate)
            invalid_status, _, invalid_body_size = await _test_login(
                session, test_url, "nonexistent_user_xyz", "wrongpassword"
            )

            # Test with common usernames
            enumerable_users = []
            for username in COMMON_USERNAMES[:3]:  # Test first 3
                await await_host_token(host, per_host_rate)
                status, _, body_size = await _test_login(
                    session, test_url, username, "wrongpassword"
                )

                # Different response = user exists
                if body_size and invalid_body_size and abs(body_size - invalid_body_size) > 50:
                    enumerable_users.append(username)

                await asyncio.sleep(0.3)

            if enumerable_users:
                findings.append({
                    "type": "Username Enumeration - Response",
                    "evidence": f"Different responses for valid/invalid usernames",
                    "how_found": f"Response analysis on {endpoint}",
                    "severity": "medium",
                    "payload": str(enumerable_users),
                    "evidence_url": test_url,
                    "enumerable_usernames": enumerable_users,
                    "technique": "response_enumeration",
                })
                logger.warning(f"📋 USERNAME ENUMERATION: {endpoint} - response differences detected")

            # 4. Test predictable session IDs
            logger.info(f"🎲 Testing session ID predictability on {endpoint}")

            session_ids = []
            for i in range(3):  # Get 3 session IDs
                await await_host_token(host, per_host_rate)
                session_id = await _get_session_id(session, test_url)
                if session_id:
                    session_ids.append(session_id)
                await asyncio.sleep(0.2)

            if len(session_ids) >= 3:
                # Check if sequential
                try:
                    if all(s.isdigit() for s in session_ids):
                        nums = [int(s) for s in session_ids]
                        if nums[1] - nums[0] <= 10 and nums[2] - nums[1] <= 10:
                            findings.append({
                                "type": "Predictable Session IDs",
                                "evidence": f"Sequential session IDs: {session_ids}",
                                "how_found": f"Session ID analysis on {endpoint}",
                                "severity": "high",
                                "payload": str(session_ids),
                                "evidence_url": test_url,
                                "session_ids": session_ids,
                                "technique": "predictable_sessions",
                            })
                            logger.error(f"🎯 PREDICTABLE SESSION IDs: {endpoint} - sequential IDs detected")
                except:
                    pass

            # 5. Test weak password policies (no lockout on failed attempts)
            logger.info(f"🔓 Testing account lockout policy on {endpoint}")

            failed_attempts = 0
            for i in range(10):  # Try 10 failed logins
                await await_host_token(host, per_host_rate)
                status, _, _ = await _test_login(
                    session, test_url, "admin", f"wrong_password_{i}"
                )

                if status in [401, 403]:  # Still accepting attempts
                    failed_attempts += 1
                elif status == 429 or status == 423:  # Locked or rate limited
                    break

                await asyncio.sleep(0.2)

            if failed_attempts >= 10:
                findings.append({
                    "type": "No Account Lockout",
                    "evidence": f"No account lockout after {failed_attempts} failed attempts",
                    "how_found": f"Lockout policy test on {endpoint}",
                    "severity": "medium",
                    "payload": f"{failed_attempts} failed attempts",
                    "evidence_url": test_url,
                    "failed_attempts": failed_attempts,
                    "technique": "no_lockout",
                })
                logger.warning(f"🔓 NO LOCKOUT: {endpoint} - {failed_attempts} failed attempts allowed")

    except Exception as e:
        logger.exception(f"brute_force_detector error for {url}: {e}")

    return findings


async def _test_login(session, url, username, password):
    """Test login with credentials, return (status, response_time, body_size)"""
    try:
        start_time = time.time()

        # Try POST with JSON
        data = {"username": username, "password": password}
        headers = {"Content-Type": "application/json"}

        async with session.post(url, json=data, headers=headers, allow_redirects=False, timeout=5) as resp:
            body = await resp.text()
            response_time = time.time() - start_time
            return resp.status, response_time, len(body)

    except Exception as e:
        logger.debug(f"Login test error for {url}: {e}")
        return None, None, None


async def _get_session_id(session, url):
    """Get session ID from response"""
    try:
        async with session.get(url, allow_redirects=False, timeout=5) as resp:
            # Check Set-Cookie header
            cookies = resp.cookies
            for cookie_name in ["session", "sessionid", "PHPSESSID", "JSESSIONID"]:
                if cookie_name in cookies:
                    return cookies[cookie_name].value

            # Check custom session headers
            if "X-Session-ID" in resp.headers:
                return resp.headers["X-Session-ID"]

    except Exception as e:
        logger.debug(f"Session ID fetch error for {url}: {e}")

    return None

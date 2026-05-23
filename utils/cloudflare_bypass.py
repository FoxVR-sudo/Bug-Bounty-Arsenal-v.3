"""
Cloudflare and CDN bypass utilities

This module provides techniques to bypass common CDN protections:
- User-Agent rotation with realistic browser signatures
- Request timing and delays to mimic human behavior
- Cookie persistence across requests
- Realistic HTTP headers matching real browsers
- TLS fingerprint variation

Usage:
    bypass = CloudflareBypass(delay_range=(2, 5))
    headers = bypass.get_headers()
    await bypass.delay()
"""

import random
import asyncio
import logging
from typing import Dict, Tuple, Optional
import aiohttp

logger = logging.getLogger(__name__)


class CloudflareBypass:
    """
    Bypass Cloudflare and CDN protections using realistic browser behavior
    """

    # Real browser User-Agent strings (recent versions)
    USER_AGENTS = [
        # Chrome on Windows
        (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        ),
        (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/119.0.0.0 Safari/537.36'
        ),
        # Chrome on macOS
        (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        ),
        (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/119.0.0.0 Safari/537.36'
        ),
        # Firefox on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        # Firefox on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari on macOS
        (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) '
            'Version/17.1 Safari/605.1.15'
        ),
        (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) '
            'Version/17.0 Safari/605.1.15'
        ),
        # Edge on Windows
        (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
        ),
        # Chrome on Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]

    # Browser-specific accept headers
    ACCEPT_HEADERS = {
        'chrome': (
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
            'application/signed-exchange;v=b3;q=0.7'
        ),
        "firefox": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "safari": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    ACCEPT_LANGUAGE = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en;q=0.9",
    ]

    ACCEPT_ENCODING = "gzip, deflate, br"

    def __init__(
        self,
        delay_range: Tuple[float, float] = (1.0, 3.0),
        rotate_user_agent: bool = True,
        use_realistic_headers: bool = True
    ):
        """
        Initialize Cloudflare bypass

        Args:
            delay_range: (min, max) seconds to wait between requests
            rotate_user_agent: Whether to rotate User-Agent per request
            use_realistic_headers: Whether to use browser-like headers
        """
        self.delay_range = delay_range
        self.rotate_user_agent = rotate_user_agent
        self.use_realistic_headers = use_realistic_headers
        self.current_user_agent = random.choice(self.USER_AGENTS)
        self.request_count = 0

    def get_browser_type(self, user_agent: str) -> str:
        """Detect browser type from User-Agent"""
        ua_lower = user_agent.lower()
        if "firefox" in ua_lower:
            return "firefox"
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            return "safari"
        else:
            return "chrome"

    def get_headers(self, referer: Optional[str] = None) -> Dict[str, str]:
        """
        Get realistic browser headers

        Args:
            referer: Optional referer header

        Returns:
            Dictionary of HTTP headers
        """
        if self.rotate_user_agent or self.request_count == 0:
            self.current_user_agent = random.choice(self.USER_AGENTS)

        browser_type = self.get_browser_type(self.current_user_agent)

        headers = {
            "User-Agent": self.current_user_agent,
            "Accept": self.ACCEPT_HEADERS.get(browser_type, self.ACCEPT_HEADERS["chrome"]),
            "Accept-Language": random.choice(self.ACCEPT_LANGUAGE),
            "Accept-Encoding": self.ACCEPT_ENCODING,
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        if referer:
            headers["Referer"] = referer
            headers["Sec-Fetch-Site"] = "same-origin"

        # Add browser-specific headers
        if browser_type == "chrome":
            headers["sec-ch-ua"] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
            headers["sec-ch-ua-mobile"] = "?0"
            headers["sec-ch-ua-platform"] = '"Windows"'

        self.request_count += 1
        return headers

    async def delay(self):
        """
        Wait for a random delay between requests to mimic human behavior
        """
        if self.delay_range[0] > 0:
            wait_time = random.uniform(self.delay_range[0], self.delay_range[1])
            logger.debug(f"Cloudflare bypass: waiting {wait_time:.2f}s before next request")
            await asyncio.sleep(wait_time)

    def create_session_kwargs(self) -> Dict:
        """
        Create kwargs for aiohttp.ClientSession with bypass features

        Returns:
            Dictionary of session configuration
        """
        kwargs = {
            "headers": self.get_headers(),
            "cookie_jar": aiohttp.CookieJar(),  # Persist cookies across requests
        }
        return kwargs

    @staticmethod
    def is_cloudflare_challenge(body: str, headers: Dict) -> bool:
        """
        Detect if response is a Cloudflare challenge page

        Args:
            body: Response body text
            headers: Response headers

        Returns:
            True if Cloudflare challenge detected
        """
        if not body:
            return False

        body_lower = body.lower()

        # Cloudflare challenge indicators
        challenge_indicators = [
            "just a moment",
            "checking your browser",
            "cloudflare",
            "ray id:",
            "cf-ray",
            "enable javascript and cookies",
            "ddos protection by cloudflare",
            "attention required",
            "checking if the site connection is secure",
        ]

        # Check body for challenge indicators
        if any(indicator in body_lower for indicator in challenge_indicators):
            return True

        # Check headers for Cloudflare
        server = headers.get("Server", "").lower()
        cf_ray = headers.get("CF-RAY", "")

        if "cloudflare" in server or cf_ray:
            # Additional check: is this an actual challenge or just CF-protected content?
            if any(indicator in body_lower for indicator in challenge_indicators[:5]):
                return True

        return False

    @staticmethod
    def extract_cloudflare_cookies(response: aiohttp.ClientResponse) -> Dict[str, str]:
        """
        Extract Cloudflare-specific cookies from response

        Args:
            response: aiohttp response object

        Returns:
            Dictionary of relevant cookies
        """
        cookies = {}
        for cookie in response.cookies.values():
            name = cookie.key
            # Cloudflare cookies typically start with cf_ or __cf
            if name.startswith(("cf_", "__cf", "__cfduid")):
                cookies[name] = cookie.value
        return cookies


def get_bypass_config(
    enable_bypass: bool = True,
    delay_min: float = 1.0,
    delay_max: float = 3.0,
    rotate_ua: bool = True
) -> Optional[CloudflareBypass]:
    """
    Create CloudflareBypass instance with given configuration

    Args:
        enable_bypass: Whether to enable bypass features
        delay_min: Minimum delay between requests (seconds)
        delay_max: Maximum delay between requests (seconds)
        rotate_ua: Whether to rotate User-Agent

    Returns:
        CloudflareBypass instance or None if disabled
    """
    if not enable_bypass:
        return None

    return CloudflareBypass(
        delay_range=(delay_min, delay_max),
        rotate_user_agent=rotate_ua,
        use_realistic_headers=True
    )

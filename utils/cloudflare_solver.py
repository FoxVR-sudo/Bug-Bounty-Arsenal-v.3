"""Cloudflare JS challenge solver using Playwright.

This module launches a temporary headless Chromium instance via Playwright
to solve Cloudflare "Just a moment" style challenges. The solver collects
resulting cookies (e.g. cf_clearance) and returns them so the aiohttp
session can reuse the authenticated context.
"""
import asyncio
import logging
from typing import Dict, Optional, Any

try:
    from playwright.async_api import async_playwright, TimeoutError
except ImportError:  # Playwright optional
    async_playwright = None  # type: ignore

    class PlaywrightTimeoutError(Exception):
        """Fallback placeholder when Playwright is unavailable."""


class CloudflareSolver:
    """Resolve Cloudflare browser challenges via Playwright."""

    def __init__(self, headless: bool = True, wait_timeout: float = 30.0):
        self.headless = headless
        self.wait_timeout = wait_timeout
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger(__name__)
        self.stats = {
            "attempts": 0,
            "success": 0,
            "failures": 0,
            "playwright_missing": False,
        }

    async def solve(self, url: str, proxy: Optional[str] = None) -> Dict[str, Any]:
        """Attempt to solve Cloudflare challenge for the given URL."""
        if async_playwright is None:
            self.stats["playwright_missing"] = True
            return {"success": False, "error": "playwright_missing"}

        async with self._lock:
            self.stats["attempts"] += 1
            browser = None
            context = None
            try:
                async with async_playwright() as p:  # type: ignore
                    launch_kwargs: Dict[str, Any] = {
                        "headless": self.headless,
                        "args": [
                            "--disable-blink-features=AutomationControlled",
                            "--disable-dev-shm-usage",
                            "--disable-extensions",
                        ],
                    }
                    if proxy:
                        launch_kwargs["proxy"] = {"server": proxy}

                    browser = await p.chromium.launch(**launch_kwargs)
                    context = await browser.new_context(locale="en-US")
                    page = await context.new_page()

                    response = None
                    try:
                        response = await page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=self.wait_timeout * 1000,
                        )
                        await page.wait_for_load_state("networkidle", timeout=self.wait_timeout * 1000)
                    except TimeoutError:
                        # Continue even if we hit timeout; cookies may still be issued
                        self.logger.debug("Cloudflare solver timeout while waiting for %s", url)
                    except Exception as exc:  # pragma: no cover - defensive against Playwright quirks
                        self.logger.debug("Cloudflare solver goto error for %s: %s", url, exc)

                    await page.wait_for_timeout(3000)  # allow challenge JS to finish

                    cookies_list = await context.cookies()
                    cookies: Dict[str, str] = {}
                    for cookie in cookies_list:
                        name = cookie.get("name")  # type: ignore[attr-defined]
                        value = cookie.get("value")  # type: ignore[attr-defined]
                        if isinstance(name, str) and isinstance(value, str):
                            cookies[name] = value
                    user_agent = await page.evaluate("() => navigator.userAgent")
                    page_url = page.url
                    response_status = response.status if response else None

                    solved = any(name.startswith(("cf", "__cf")) for name in cookies.keys())
                    if not solved and page_url and page_url != url:
                        # Cloudflare typically redirects back to target on success
                        solved = True

                    result = {
                        "success": bool(solved),
                        "cookies": cookies,
                        "user_agent": user_agent,
                        "headers": {
                            "User-Agent": user_agent,
                            "Referer": page_url,
                        },
                        "page_url": page_url,
                        "status": response_status,
                    }

                    if solved:
                        self.stats["success"] += 1
                    else:
                        self.stats["failures"] += 1

                    return result
            except Exception as exc:  # pragma: no cover
                self.stats["failures"] += 1
                self.logger.exception("Cloudflare solver error for %s: %s", url, exc)
                return {"success": False, "error": str(exc)}
            finally:
                try:
                    if context:
                        await context.close()
                except Exception:
                    pass
                try:
                    if browser:
                        await browser.close()
                except Exception:
                    pass

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregated solver statistics."""
        return dict(self.stats)

"""DOM analyzer using Playwright for headless browser inspections."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from playwright.async_api import (  # type: ignore
        Browser,
        BrowserContext,
        Error as PlaywrightError,
        Page,
        TimeoutError as PlaywrightTimeoutError,
        async_playwright,
    )
except ImportError:  # pragma: no cover - handled at runtime
    Browser = BrowserContext = Page = Any  # type: ignore
    PlaywrightError = PlaywrightTimeoutError = Exception  # type: ignore
    async_playwright = None  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class DOMFinding:
    url: str
    final_url: Optional[str]
    status: Optional[int]
    title: Optional[str]
    load_time: Optional[float]
    screenshot_path: Optional[str]
    console_messages: List[Dict[str, Any]]
    request_failures: List[Dict[str, Any]]
    dom_sinks: Dict[str, List[Dict[str, Any]]]


class DOMPlaywrightScanner:
    """Runs Playwright to capture DOM evidence for client-side issues."""

    def __init__(
        self,
        *,
        headless: bool = True,
        wait_until: str = "networkidle",
        nav_timeout_ms: int = 15000,
        capture_screenshots: bool = True,
    ) -> None:
        self.headless = headless
        self.wait_until = wait_until
        self.nav_timeout_ms = nav_timeout_ms
        self.capture_screenshots = capture_screenshots

    @staticmethod
    def check_prerequisites() -> bool:
        if async_playwright is None:
            logger.error(
                "Playwright is not installed. Install it with 'pip install playwright' and run 'playwright install chromium'."
            )
            return False
        return True

    async def _scan_single(self, page: Any, url: str, screenshot_dir: Path) -> DOMFinding:
        console_messages: List[Dict[str, Any]] = []
        request_failures: List[Dict[str, Any]] = []

        def _console_handler(msg) -> None:
            console_messages.append({
                "type": msg.type,
                "text": msg.text,
                "location": msg.location,
            })

        def _request_failed(req) -> None:
            request_failures.append({
                "url": req.url,
                "method": req.method,
                "failure": req.failure.value if req.failure else None,
            })

        page.on("console", _console_handler)
        page.on("requestfailed", _request_failed)

        status: Optional[int] = None
        final_url: Optional[str] = None
        title: Optional[str] = None
        load_time: Optional[float] = None
        screenshot_path: Optional[Path] = None

        try:
            logger.debug("Playwright navigating to %s", url)
            start_ts = time.perf_counter()
            response = await page.goto(
                url,
                wait_until=self.wait_until,
                timeout=self.nav_timeout_ms,
            )
            if response:
                status = response.status
            final_url = page.url
            title = await page.title()
            load_time = time.perf_counter() - start_ts

            dom_sinks = await page.evaluate(
                r"""
                () => {
                    const riskyNodeRegex = /(location\.(hash|search)|document\.(URL|cookie)|window\.name|localStorage|sessionStorage)/i;
                    const riskyScriptRegex = /(innerHTML|outerHTML|document\.write|eval|Function|setTimeout|setInterval)[^;]*\(([^)]*location|document\.(URL|cookie))/i;
                    const sinks = { nodeHits: [], scriptHits: [] };

                    const root = document.body || document.documentElement;
                    if (root) {
                        const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
                        while (walker.nextNode()) {
                            const node = walker.currentNode;
                            for (const attribute of ["innerHTML", "outerHTML"]) {
                                const value = node[attribute];
                                if (typeof value === "string" && riskyNodeRegex.test(value)) {
                                    sinks.nodeHits.push({
                                        tag: node.tagName,
                                        attribute,
                                        snippet: value.slice(0, 180),
                                    });
                                    break;
                                }
                            }
                        }
                    }

                    const scripts = Array.from(document.querySelectorAll("script"));
                    scripts.forEach((script, index) => {
                        const text = script.textContent || "";
                        if (text && riskyScriptRegex.test(text)) {
                            sinks.scriptHits.push({
                                index,
                                snippet: text.slice(0, 200),
                            });
                        }
                    });

                    return sinks;
                }
                """
            )

            if self.capture_screenshots:
                screenshot_dir.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
                screenshot_path = screenshot_dir / f"{digest}.png"
                try:
                    await page.screenshot(path=str(screenshot_path), full_page=True)
                except PlaywrightError as err:
                    logger.debug("Screenshot failed for %s: %s", url, err)
                    screenshot_path = None

            findings = DOMFinding(
                url=url,
                final_url=final_url,
                status=status,
                title=title,
                load_time=load_time,
                screenshot_path=str(screenshot_path) if screenshot_path else None,
                console_messages=console_messages,
                request_failures=request_failures,
                dom_sinks=dom_sinks or {"nodeHits": [], "scriptHits": []},
            )
            return findings

        except PlaywrightTimeoutError:
            logger.debug("Playwright navigation timeout for %s", url)
            return DOMFinding(
                url=url,
                final_url=final_url,
                status=status,
                title=title,
                load_time=load_time,
                screenshot_path=None,
                console_messages=console_messages,
                request_failures=request_failures,
                dom_sinks={"nodeHits": [], "scriptHits": []},
            )
        except PlaywrightError as err:
            logger.debug("Playwright error for %s: %s", url, err)
            return DOMFinding(
                url=url,
                final_url=final_url,
                status=status,
                title=title,
                load_time=load_time,
                screenshot_path=None,
                console_messages=console_messages,
                request_failures=request_failures,
                dom_sinks={"nodeHits": [], "scriptHits": []},
            )

    async def scan_urls(self, urls: List[str], output_dir: Path) -> List[Dict[str, Any]]:
        output_dir.mkdir(parents=True, exist_ok=True)
        screenshot_dir = output_dir / "screenshots"

        async with async_playwright() as p:  # type: ignore
            try:
                browser = await p.chromium.launch(headless=self.headless)
            except PlaywrightError as err:
                raise RuntimeError(
                    "Failed to launch Chromium via Playwright. Install browsers with 'playwright install chromium'."
                ) from err

            context = await browser.new_context()
            results: List[Dict[str, Any]] = []

            try:
                for url in urls:
                    page = await context.new_page()
                    finding = await self._scan_single(page, url, screenshot_dir)
                    results.append(finding.__dict__)
                    await page.close()
            finally:
                await context.close()
                await browser.close()

        # Persist aggregated JSON for convenience
        output_file = output_dir / "dom_playwright_results.json"
        output_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
        return results


def run_dom_playwright_scan(urls: List[str], output_dir: str, *, headless: bool = True) -> Dict[str, Any]:
    scanner = DOMPlaywrightScanner(headless=headless)
    if not scanner.check_prerequisites():
        return {"error": "playwright_missing"}

    async def _runner() -> List[Dict[str, Any]]:
        return await scanner.scan_urls(urls, Path(output_dir))

    try:
        try:
            results = asyncio.run(_runner())
        except RuntimeError as runtime_error:
            if "asyncio.run()" in str(runtime_error):
                loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(loop)
                    results = loop.run_until_complete(_runner())
                finally:
                    asyncio.set_event_loop(None)
                    loop.close()
            else:
                raise
    except Exception as exc:
        logger.error("Playwright DOM scan failed: %s", exc)
        return {"error": str(exc)}

    finding_count = sum(
        len(entry.get("dom_sinks", {}).get("nodeHits", []))
        + len(entry.get("dom_sinks", {}).get("scriptHits", []))
        + sum(1 for msg in entry.get("console_messages", []) if msg.get("type") == "error")
        for entry in results
    )

    return {
        "results": results,
        "urls_tested": len(results),
        "potential_issues": finding_count,
        "output_dir": output_dir,
    }

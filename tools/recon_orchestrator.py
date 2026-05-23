"""
Recon orchestrator - coordinates Subfinder, HTTPX, Scanner, and Nuclei.

Pipeline:
1. Subfinder: Enumerate subdomains
2. HTTPX: Probe live web servers
3. Scanner: Deep vulnerability scanning (22+ detectors)
4. Playwright DOM audit (optional)
5. Exploit validation (optional)
6. Nuclei: Template-based vulnerability scanning
"""
import asyncio
import logging
import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime
from dataclasses import asdict

import aiohttp

from tools.external_tools import (
    SubfinderWrapper,
    HTTPXWrapper,
    NucleiWrapper,
    check_tool_installation,
    print_installation_instructions
)
from tools.improved_exploit_scanner import ImprovedExploitScanner
from tools.dom_playwright_scanner import run_dom_playwright_scan

logger = logging.getLogger(__name__)


class ReconOrchestrator:
    """Orchestrates the full reconnaissance and scanning pipeline."""

    def __init__(self, output_dir: str = "recon_output", job_id: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

        # Initialize tool wrappers
        self.subfinder = SubfinderWrapper()
        self.httpx = HTTPXWrapper()
        self.nuclei = NucleiWrapper()
        self.exploit_scanner: Optional[ImprovedExploitScanner] = None

        # Check tool installation
        self.tools_status = check_tool_installation()

        # Progress tracking
        self.job_id = job_id
        self.progress_file = None
        if self.job_id:
            import os
            progress_dir = "scan_progress"
            os.makedirs(progress_dir, exist_ok=True)
            self.progress_file = os.path.join(progress_dir, f"{self.job_id}.json")
            # Initialize progress
            self._update_progress(0, 0, 0, 0)

    def _update_progress(self, total_urls: int, urls_scanned: int, findings: int, progress_pct: int):
        """Update progress file for web UI."""
        if not self.progress_file:
            return
        import json
        import time
        try:
            with open(self.progress_file, 'w') as f:
                json.dump({
                    "total_urls": total_urls,
                    "urls_scanned": urls_scanned,
                    "progress_percentage": progress_pct,
                    "vulnerabilities_found": findings,
                    "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }, f)
        except Exception:
            pass

    def check_prerequisites(self) -> bool:
        """
        Check if all required tools are installed.
        Docker deployment includes all tools pre-installed.

        Returns:
            True if all tools are available, False otherwise
        """
        all_installed = all(self.tools_status.values())

        if not all_installed:
            missing = [name for name, installed in self.tools_status.items() if not installed]
            logger.error(f"⚠️  Missing required tools: {', '.join(missing)}")
            logger.error("Please ensure Docker container is running with all tools installed.")
            print_installation_instructions()
            return False

        logger.info("✓ All recon tools are installed and ready")
        return True

    def run_full_recon(
        self,
        domain: str,
        run_scanner: bool = True,
        run_nuclei: bool = True,
        nuclei_severity: Optional[List[str]] = None,
        scanner_concurrency: int = 10,
        nuclei_rate_limit: int = 150,
        recursive_subs: bool = False,
        allow_destructive: bool = False,
        bypass_cloudflare: bool = False,
        bypass_delay_min: float = 1.0,
        bypass_delay_max: float = 3.0,
        enable_dom_playwright: bool = False,
        enable_exploit_validation: bool = False,
        enable_403_probe: bool = False,
        enable_cloudflare_solver: bool = False,
    ):
        """
        Run the full reconnaissance pipeline.

        Args:
            domain: Target domain (e.g., "example.com")
            run_scanner: Whether to run the custom scanner
            run_nuclei: Whether to run Nuclei
            nuclei_severity: Filter Nuclei by severity (e.g., ["high", "critical"])
            scanner_concurrency: Concurrency for custom scanner
            nuclei_rate_limit: Rate limit for Nuclei
            recursive_subs: Use recursive subdomain enumeration
            bypass_cloudflare: Enable Cloudflare/CDN bypass
            bypass_delay_min: Minimum delay between requests (seconds)
            bypass_delay_max: Maximum delay between requests (seconds)
            enable_dom_playwright: Run optional Playwright DOM audit for client-side issues
            enable_exploit_validation: Run optional exploit validation (Exploit-DB + PoC filtering)
            enable_403_probe: Attempt common HTTP 403 bypass heuristics during scanning
            enable_cloudflare_solver: Attempt to automatically solve Cloudflare browser challenges

        Returns:
            Dictionary with all findings and metadata
        """
        if not self.check_prerequisites():
            return {"error": "Missing required tools"}

        start_time = time.time()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create domain-specific output directory
        domain_output = self.output_dir / domain / timestamp
        domain_output.mkdir(parents=True, exist_ok=True)

        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "phases": {}
        }

        # Determine number of phases for progress messages
        total_phases = 2
        if run_scanner:
            total_phases += 1
        if enable_dom_playwright:
            total_phases += 1
        if enable_exploit_validation:
            total_phases += 1
        if run_nuclei:
            total_phases += 1
        phase_index = 1

        # Phase 1: Subdomain Enumeration
        logger.info(f"[Phase {phase_index}/{total_phases}] Enumerating subdomains for {domain}...")
        phase_start = time.time()

        subdomains = self.subfinder.enumerate_subdomains(
            domain,
            recursive=recursive_subs,
            timeout=600  # Increased from 300s to 600s for large targets like GitHub
        )

        if not subdomains:
            logger.warning(f"No subdomains found for {domain}")
            # Ensure UI reflects completion instead of hanging at 0-25%
            try:
                # We treat this as an immediate completion with 0 findings
                self._update_progress(1, 1, 0, 100)
            except Exception:
                pass
            return {"error": "No subdomains discovered"}

        subs_file = domain_output / f"{phase_index:02d}_subdomains.txt"
        subs_file.write_text("\n".join(subdomains))

        results["phases"]["subdomain_enumeration"] = {
            "duration": time.time() - phase_start,
            "subdomains_found": len(subdomains),
            "output_file": str(subs_file)
        }

        logger.info(f"✓ Found {len(subdomains)} subdomains in {time.time() - phase_start:.1f}s")
        self._update_progress(total_phases, 1, 0, 25)  # 25% after Phase 1
        phase_index += 1

        # Phase 2: HTTP Probing
        logger.info(f"[Phase {phase_index}/{total_phases}] Probing {len(subdomains)} hosts with HTTPX...")
        phase_start = time.time()

        live_hosts = self.httpx.probe_hosts(
            subdomains,
            threads=50,
            timeout=10
        )

        if not live_hosts:
            logger.warning("No live hosts found")
            # Mark progress as completed so UI doesn't stick at 25%
            try:
                self._update_progress(total_phases, 2, 0, 100)
            except Exception:
                pass
            return results

        live_file = domain_output / f"{phase_index:02d}_live_hosts.json"
        live_file.write_text(json.dumps(live_hosts, indent=2))

        live_urls = [h["url"] for h in live_hosts if h.get("url")]

        results["phases"]["http_probing"] = {
            "duration": time.time() - phase_start,
            "hosts_probed": len(subdomains),
            "live_hosts": len(live_hosts),
            "output_file": str(live_file)
        }

        logger.info(f"✓ Found {len(live_hosts)} live hosts in {time.time() - phase_start:.1f}s")
        self._update_progress(total_phases, 2, 0, 50)  # 50% after Phase 2
        phase_index += 1

        # Phase 3: Custom Scanner (our 22+ detectors)
        if run_scanner:
            phase_label = f"[Phase {phase_index}/{total_phases}]"
            if live_urls:
                logger.info(f"{phase_label} Running custom scanner on {len(live_urls)} URLs...")
                phase_start = time.time()

                try:
                    import scanner

                    scanner_results, scanner_meta = scanner.run_scan(
                        live_urls,
                        concurrency=scanner_concurrency,
                        timeout=15,
                        output_dir=str(domain_output / "scanner_responses"),
                        per_host_rate=1.0,
                        allow_destructive=allow_destructive,
                        bypass_cloudflare=bypass_cloudflare,
                        bypass_delay_min=bypass_delay_min,
                        bypass_delay_max=bypass_delay_max,
                        enable_forbidden_probe=enable_403_probe,
                        enable_cloudflare_solver=enable_cloudflare_solver,
                    )

                    scanner_file = domain_output / f"{phase_index:02d}_scanner_findings.json"
                    scanner_output = {
                        "results": scanner_results,
                        "metadata": scanner_meta
                    }
                    scanner_file.write_text(json.dumps(scanner_output, indent=2))

                    severity_counts: Dict[str, int] = {}
                    for finding in scanner_results:
                        sev = finding.get("severity", "unknown")
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1

                    results["phases"]["custom_scanner"] = {
                        "duration": time.time() - phase_start,
                        "urls_scanned": len(live_urls),
                        "findings": len(scanner_results),
                        "by_severity": severity_counts,
                        "output_file": str(scanner_file)
                    }

                    logger.info(
                        f"✓ Scanner found {len(scanner_results)} issues in {time.time() - phase_start:.1f}s"
                    )
                    self._update_progress(total_phases, 3, len(scanner_results), 75)  # 75% after Phase 3

                except Exception as exc:
                    logger.error(f"Scanner phase failed: {exc}")
                    results["phases"]["custom_scanner"] = {"error": str(exc)}
            else:
                logger.info(f"{phase_label} Skipping custom scanner (no live URLs)")
                results["phases"]["custom_scanner"] = {"skipped": "no_live_hosts"}
            phase_index += 1

        # Phase 4: Playwright DOM audit (optional)
        if enable_dom_playwright:
            phase_label = f"[Phase {phase_index}/{total_phases}]"
            if live_urls:
                logger.info(f"{phase_label} Running Playwright DOM audit on {len(live_urls)} URLs...")
                phase_start = time.time()

                try:
                    dom_stage_dir = domain_output / f"{phase_index:02d}_dom_playwright"
                    summary = run_dom_playwright_scan(live_urls, str(dom_stage_dir))

                    if "error" in summary:
                        error_code = summary.get("error")
                        if error_code == "playwright_missing":
                            logger.warning("Playwright is not available; skipping DOM audit phase.")
                            results["phases"]["dom_playwright"] = {
                                "skipped": "playwright_missing",
                                "urls_considered": len(live_urls),
                            }
                        else:
                            results["phases"]["dom_playwright"] = {"error": error_code}
                    else:
                        results["phases"]["dom_playwright"] = {
                            "duration": time.time() - phase_start,
                            "urls_tested": summary.get("urls_tested", 0),
                            "potential_issues": summary.get("potential_issues", 0),
                            "output_dir": summary.get("output_dir"),
                        }

                        logger.info(
                            "✓ Playwright DOM audit completed in %.1fs (potential issues: %s)",
                            time.time() - phase_start,
                            summary.get("potential_issues", 0),
                        )

                except Exception as exc:
                    logger.error("Playwright DOM audit failed: %s", exc)
                    results["phases"]["dom_playwright"] = {"error": str(exc)}
            else:
                logger.info(f"{phase_label} Skipping Playwright DOM audit (no live URLs)")
                results["phases"]["dom_playwright"] = {"skipped": "no_live_hosts"}
            phase_index += 1

        # Phase 5: Exploit validation (optional)
        if enable_exploit_validation:
            phase_label = f"[Phase {phase_index}/{total_phases}]"
            if live_urls:
                logger.info(f"{phase_label} Running exploit validation on {len(live_urls)} URLs...")
                phase_start = time.time()

                try:
                    if self.exploit_scanner is None:
                        self.exploit_scanner = ImprovedExploitScanner()

                    exploit_scanner = self.exploit_scanner

                    if not exploit_scanner.check_prerequisites():
                        logger.warning("Exploit-DB not available; skipping exploit validation phase.")
                        results["phases"]["exploit_validation"] = {
                            "skipped": "exploitdb_not_found",
                            "urls_considered": len(live_urls)
                        }
                    else:
                        async def _run_validation(targets: List[str]):
                            timeout = aiohttp.ClientTimeout(total=20)
                            entries: List[Dict[str, Any]] = []
                            async with aiohttp.ClientSession(timeout=timeout) as session:
                                for target_url in targets:
                                    entry: Dict[str, Any] = {"url": target_url, "findings": []}
                                    try:
                                        vulns = await exploit_scanner.scan_target(target_url, session)
                                        entry["findings"] = [asdict(v) for v in vulns]
                                    except Exception as scan_exc:
                                        entry["error"] = str(scan_exc)
                                    entries.append(entry)
                            return entries

                        try:
                            exploit_results = asyncio.run(_run_validation(live_urls))
                        except RuntimeError as runtime_error:
                            if "asyncio.run()" in str(runtime_error):
                                loop = asyncio.new_event_loop()
                                try:
                                    asyncio.set_event_loop(loop)
                                    exploit_results = loop.run_until_complete(_run_validation(live_urls))
                                finally:
                                    asyncio.set_event_loop(None)
                                    loop.close()
                            else:
                                raise

                        vulnerable_urls = sum(1 for entry in exploit_results if entry.get("findings"))
                        total_findings = sum(len(entry.get("findings", [])) for entry in exploit_results)

                        exploit_file = domain_output / f"{phase_index:02d}_exploit_validation.json"
                        exploit_file.write_text(json.dumps(exploit_results, indent=2))

                        results["phases"]["exploit_validation"] = {
                            "duration": time.time() - phase_start,
                            "urls_tested": len(live_urls),
                            "vulnerable_urls": vulnerable_urls,
                            "findings": total_findings,
                            "output_file": str(exploit_file)
                        }

                        logger.info(
                            f"✓ Exploit validation identified {total_findings} PoC-backed issues across "
                            f"{vulnerable_urls} URLs in {time.time() - phase_start:.1f}s"
                        )

                except Exception as exc:
                    logger.error(f"Exploit validation phase failed: {exc}")
                    results["phases"]["exploit_validation"] = {"error": str(exc)}
            else:
                logger.info(f"{phase_label} Skipping exploit validation (no live URLs)")
                results["phases"]["exploit_validation"] = {"skipped": "no_live_hosts"}
            phase_index += 1

        # Final phase: Nuclei scanning
        if run_nuclei:
            phase_label = f"[Phase {phase_index}/{total_phases}]"
            if live_urls:
                logger.info(f"{phase_label} Running Nuclei on {len(live_urls)} URLs...")
                phase_start = time.time()

                try:
                    nuclei_findings = self.nuclei.scan_targets(
                        live_urls,
                        severity=nuclei_severity or ["low", "medium", "high", "critical"],
                        rate_limit=nuclei_rate_limit,
                        timeout=600
                    )

                    nuclei_file = domain_output / f"{phase_index:02d}_nuclei_findings.json"
                    nuclei_file.write_text(json.dumps(nuclei_findings, indent=2))

                    nuclei_severity_counts: Dict[str, int] = {}
                    for finding in nuclei_findings:
                        sev = finding.get("severity", "unknown")
                        nuclei_severity_counts[sev] = nuclei_severity_counts.get(sev, 0) + 1

                    results["phases"]["nuclei"] = {
                        "duration": time.time() - phase_start,
                        "urls_scanned": len(live_urls),
                        "findings": len(nuclei_findings),
                        "by_severity": nuclei_severity_counts,
                        "output_file": str(nuclei_file)
                    }

                    logger.info(
                        f"✓ Nuclei found {len(nuclei_findings)} issues in {time.time() - phase_start:.1f}s"
                    )

                except Exception as exc:
                    logger.error(f"Nuclei phase failed: {exc}")
                    results["phases"]["nuclei"] = {"error": str(exc)}
            else:
                logger.info(f"{phase_label} Skipping Nuclei (no live URLs)")
                results["phases"]["nuclei"] = {"skipped": "no_live_hosts"}
            phase_index += 1

        # Save final results
        results["total_duration"] = time.time() - start_time
        results["output_directory"] = str(domain_output)

        summary_file = domain_output / "00_recon_summary.json"
        summary_file.write_text(json.dumps(results, indent=2))

        logger.info(f"\n{'='*70}")
        logger.info(f"✓ Full recon completed in {results['total_duration']:.1f}s")
        logger.info(f"✓ Output directory: {domain_output}")
        logger.info(f"{'='*70}\n")

        # Print summary
        self._print_summary(results)

        # Update final progress
        total_findings = 0
        if "custom_scanner" in results["phases"]:
            total_findings += results["phases"]["custom_scanner"].get("findings", 0)
        if "nuclei" in results["phases"]:
            total_findings += results["phases"]["nuclei"].get("findings", 0)
        self._update_progress(total_phases, total_phases, total_findings, 100)

        return results

    def _print_summary(self, results: Dict[str, Any]):
        """Print a formatted summary of the recon results."""
        print("\n" + "="*70)
        print(f"RECON SUMMARY: {results['domain']}")
        print("="*70)

        phases = results.get("phases", {})

        # Subdomain enumeration
        if "subdomain_enumeration" in phases:
            sub_data = phases["subdomain_enumeration"]
            print(f"\n📡 Subdomain Enumeration:")
            print(f"   Found: {sub_data.get('subdomains_found', 0)} subdomains")
            print(f"   Time: {sub_data.get('duration', 0):.1f}s")

        # HTTP probing
        if "http_probing" in phases:
            http_data = phases["http_probing"]
            print(f"\n🌐 HTTP Probing:")
            print(f"   Probed: {http_data.get('hosts_probed', 0)} hosts")
            print(f"   Live: {http_data.get('live_hosts', 0)} hosts")
            print(f"   Time: {http_data.get('duration', 0):.1f}s")

        # Custom scanner
        if "custom_scanner" in phases:
            scanner_data = phases["custom_scanner"]
            if "error" not in scanner_data and "skipped" not in scanner_data:
                print(f"\n🔍 Custom Scanner (22+ detectors):")
                print(f"   Scanned: {scanner_data.get('urls_scanned', 0)} URLs")
                print(f"   Findings: {scanner_data.get('findings', 0)}")

                sev_counts = scanner_data.get("by_severity", {})
                if sev_counts:
                    print(f"   Severity breakdown:")
                    for sev in ["critical", "high", "medium", "low"]:
                        if sev in sev_counts:
                            print(f"      {sev.capitalize()}: {sev_counts[sev]}")

                print(f"   Time: {scanner_data.get('duration', 0):.1f}s")
            elif scanner_data.get("skipped"):
                print(f"\n🔍 Custom Scanner skipped ({scanner_data.get('skipped')}).")
            elif scanner_data.get("error"):
                print(f"\n🔍 Custom Scanner failed: {scanner_data.get('error')}")

        # DOM Playwright audit
        if "dom_playwright" in phases:
            dom_data = phases["dom_playwright"]
            if "error" not in dom_data and "skipped" not in dom_data:
                print(f"\n🧪 Playwright DOM Audit:")
                print(f"   Tested: {dom_data.get('urls_tested', 0)} URLs")
                print(f"   Potential issues: {dom_data.get('potential_issues', 0)}")
                print(f"   Time: {dom_data.get('duration', 0):.1f}s")
            elif dom_data.get("skipped"):
                print(f"\n🧪 Playwright DOM Audit skipped ({dom_data.get('skipped')}).")
            elif dom_data.get("error"):
                print(f"\n🧪 Playwright DOM Audit failed: {dom_data.get('error')}")

        # Exploit validation
        if "exploit_validation" in phases:
            exploit_data = phases["exploit_validation"]
            if "error" not in exploit_data and "skipped" not in exploit_data:
                print(f"\n💣 Exploit Validation:")
                print(f"   Tested: {exploit_data.get('urls_tested', 0)} URLs")
                print(f"   Vulnerable URLs: {exploit_data.get('vulnerable_urls', 0)}")
                print(f"   Exploitable findings: {exploit_data.get('findings', 0)}")
                print(f"   Time: {exploit_data.get('duration', 0):.1f}s")
            elif exploit_data.get("skipped"):
                reason = exploit_data.get("skipped")
                print(f"\n💣 Exploit Validation skipped ({reason}).")
            elif exploit_data.get("error"):
                print(f"\n💣 Exploit Validation failed: {exploit_data.get('error')}")

        # Nuclei
        if "nuclei" in phases:
            nuclei_data = phases["nuclei"]
            if "error" not in nuclei_data and "skipped" not in nuclei_data:
                print(f"\n⚡ Nuclei Scanner:")
                print(f"   Scanned: {nuclei_data.get('urls_scanned', 0)} URLs")
                print(f"   Findings: {nuclei_data.get('findings', 0)}")

                sev_counts = nuclei_data.get("by_severity", {})
                if sev_counts:
                    print(f"   Severity breakdown:")
                    for sev in ["critical", "high", "medium", "low", "info"]:
                        if sev in sev_counts:
                            print(f"      {sev.capitalize()}: {sev_counts[sev]}")

                print(f"   Time: {nuclei_data.get('duration', 0):.1f}s")
            elif nuclei_data.get("skipped"):
                print(f"\n⚡ Nuclei Scanner skipped ({nuclei_data.get('skipped')}).")
            elif nuclei_data.get("error"):
                print(f"\n⚡ Nuclei Scanner failed: {nuclei_data.get('error')}")

        print(f"\n⏱️  Total Time: {results.get('total_duration', 0):.1f}s")
        print(f"📁 Output: {results.get('output_directory', 'N/A')}")
        print("="*70 + "\n")


def run_recon_pipeline(
    domain: str,
    output_dir: str = "recon_output",
    skip_scanner: bool = False,
    skip_nuclei: bool = False,
    nuclei_severity: Optional[List[str]] = None,
    scanner_concurrency: int = 10,
    nuclei_rate_limit: int = 150,
    recursive_subs: bool = False,
    allow_destructive: bool = False,
    bypass_cloudflare: bool = False,
    bypass_delay_min: float = 1.0,
    bypass_delay_max: float = 3.0,
    enable_dom_playwright: bool = False,
    enable_exploit_validation: bool = False,
    enable_403_probe: bool = False,
    enable_cloudflare_solver: bool = False,
    job_id: Optional[str] = None,
) -> dict:
    """
    Convenience function to run the full recon pipeline.

    Args:
        domain: Target domain
        output_dir: Output directory for results
        skip_scanner: Skip custom scanner phase
        skip_nuclei: Skip Nuclei phase
        nuclei_severity: Filter Nuclei by severity
        scanner_concurrency: Scanner concurrency level
        nuclei_rate_limit: Nuclei rate limit
        recursive_subs: Use recursive subdomain enumeration
        bypass_cloudflare: Enable Cloudflare/CDN bypass
        bypass_delay_min: Minimum delay between requests (seconds)
        bypass_delay_max: Maximum delay between requests (seconds)
    enable_dom_playwright: Run optional Playwright DOM audit
    enable_exploit_validation: Run optional exploit validation (Exploit-DB backed)
    enable_403_probe: Attempt automatic 403 bypass heuristics during scanner phase
    enable_cloudflare_solver: Attempt Cloudflare JS challenge solving via Playwright

    Returns:
        Recon results dictionary
    """
    orchestrator = ReconOrchestrator(output_dir=output_dir, job_id=job_id)

    return orchestrator.run_full_recon(
        domain=domain,
        run_scanner=not skip_scanner,
        run_nuclei=not skip_nuclei,
        nuclei_severity=nuclei_severity,
        scanner_concurrency=scanner_concurrency,
        nuclei_rate_limit=nuclei_rate_limit,
        recursive_subs=recursive_subs,
        allow_destructive=allow_destructive,
        bypass_cloudflare=bypass_cloudflare,
        bypass_delay_min=bypass_delay_min,
        bypass_delay_max=bypass_delay_max,
        enable_dom_playwright=enable_dom_playwright,
        enable_exploit_validation=enable_exploit_validation,
        enable_403_probe=enable_403_probe,
        enable_cloudflare_solver=enable_cloudflare_solver,
    )

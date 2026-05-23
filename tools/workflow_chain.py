"""
Full Bug Bounty Workflow Chain

Implements the complete recon-to-exploitation pipeline:

  subfinder/amass  → enumerate subdomains
  httpx            → filter live hosts
  katana           → crawl all endpoints
  gf patterns      → filter juicy params (idor, ssrf, xss, sqli, redirect, lfi)
  ffuf             → fuzz IDs for IDOR
  dalfox           → automated XSS scanning on reflection candidates
  nuclei           → template-based CVE / misconfiguration scanning

Usage (programmatic):
    from tools.workflow_chain import WorkflowChain

    chain = WorkflowChain(output_dir="chain_output")
    results = chain.run(domain="target.com")

Usage (CLI):
    python -m tools.workflow_chain target.com --output chain_output
"""

import asyncio
import json
import logging
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from tools.external_tools import (
    AmassWrapper,
    DalfoxWrapper,
    FfufWrapper,
    GfWrapper,
    HTTPXWrapper,
    KatanaWrapper,
    NucleiWrapper,
    SubfinderWrapper,
    check_tool_installation,
    print_installation_instructions,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default wordlists bundled with the project (populated lazily)
# ---------------------------------------------------------------------------

_BUILTIN_WORDLISTS_DIR = Path(__file__).parent.parent / "scripts" / "wordlists"

# Tiny numeric ID wordlist for IDOR fuzzing when no external list is provided
_BUILTIN_ID_WORDLIST_CONTENT = "\n".join(str(i) for i in range(1, 1001))


def _ensure_id_wordlist(path: Optional[str]) -> str:
    """Return path to an ID wordlist; creates a built-in one if none supplied."""
    if path and Path(path).exists():
        return path

    # Check built-in location
    builtin = _BUILTIN_WORDLISTS_DIR / "ids_1_1000.txt"
    if not builtin.exists():
        builtin.parent.mkdir(parents=True, exist_ok=True)
        builtin.write_text(_BUILTIN_ID_WORDLIST_CONTENT)

    return str(builtin)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ChainResults:
    domain: str
    timestamp: str
    phases: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# WorkflowChain
# ---------------------------------------------------------------------------

class WorkflowChain:
    """
    Chains all recon and exploitation tools into a single automated pipeline.

    Phases
    ------
    1. Subdomain Enumeration  — subfinder (+ amass if installed)
    2. HTTP Probing           — httpx
    3. Crawling               — katana
    4. Pattern Filtering      — gf (idor / ssrf / xss / sqli / redirect / lfi)
    5. IDOR Fuzzing           — ffuf (numeric ID fuzzing on idor-flagged URLs)
    6. XSS Scanning           — dalfox (on xss-flagged URLs)
    7. Nuclei Scanning        — nuclei (on all live hosts)
    """

    def __init__(self, output_dir: str = "chain_output", job_id: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.job_id = job_id

        # Tool wrappers
        self.subfinder = SubfinderWrapper()
        self.amass = AmassWrapper()
        self.httpx = HTTPXWrapper()
        self.katana = KatanaWrapper()
        self.gf = GfWrapper()
        self.ffuf = FfufWrapper()
        self.dalfox = DalfoxWrapper()
        self.nuclei = NucleiWrapper()

        self.tools_status = check_tool_installation()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        domain: str,
        *,
        id_wordlist: Optional[str] = None,
        crawl_depth: int = 3,
        ffuf_threads: int = 40,
        ffuf_rate: int = 100,
        nuclei_severity: Optional[List[str]] = None,
        run_amass: bool = True,
        run_katana: bool = True,
        run_ffuf: bool = True,
        run_dalfox: bool = True,
        run_nuclei: bool = True,
        blind_xss_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute the full workflow chain against a domain.

        Args:
            domain: Root domain (e.g., "example.com")
            id_wordlist: Path to numeric ID wordlist for ffuf IDOR fuzzing
            crawl_depth: Katana crawl depth (default 3)
            ffuf_threads: Thread count for ffuf
            ffuf_rate: Max req/s for ffuf (0 = unlimited)
            nuclei_severity: e.g., ["high", "critical"]
            run_amass: Include Amass for extra subdomain coverage
            run_katana: Include Katana crawling phase
            run_ffuf: Include ffuf IDOR fuzzing phase
            run_dalfox: Include dalfox XSS phase
            run_nuclei: Include Nuclei phase
            blind_xss_url: Callback URL for blind XSS (dalfox --blind)

        Returns:
            Dictionary with all phase results and summary counts
        """
        start = time.time()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = self.output_dir / domain / ts
        out_dir.mkdir(parents=True, exist_ok=True)

        results = ChainResults(domain=domain, timestamp=datetime.now().isoformat())
        id_wl = _ensure_id_wordlist(id_wordlist)

        logger.info(f"=== WorkflowChain started for {domain} ===")

        # ---------------------------------------------------------------
        # Phase 1: Subdomain Enumeration
        # ---------------------------------------------------------------
        logger.info("[1/7] Subdomain enumeration...")
        t = time.time()

        subdomains: List[str] = []

        if self.subfinder.is_installed():
            subs = self.subfinder.enumerate_subdomains(domain, recursive=False, timeout=300)
            subdomains.extend(subs)
            logger.info(f"  subfinder → {len(subs)} subdomains")
        else:
            logger.warning("  subfinder not installed, skipping")

        if run_amass and self.amass.is_installed():
            amass_subs = self.amass.enumerate_subdomains(domain, passive=True, timeout=180)
            new_subs = [s for s in amass_subs if s not in subdomains]
            subdomains.extend(new_subs)
            logger.info(f"  amass     → {len(amass_subs)} subdomains (+{len(new_subs)} new)")
        elif run_amass:
            logger.warning("  amass not installed, skipping")

        # Deduplicate
        subdomains = list(dict.fromkeys(subdomains))

        if not subdomains:
            logger.warning("No subdomains found — adding root domain as fallback")
            subdomains = [domain]

        _write_lines(out_dir / "01_subdomains.txt", subdomains)
        results.phases["subdomain_enumeration"] = {
            "duration_s": round(time.time() - t, 1),
            "count": len(subdomains),
            "file": str(out_dir / "01_subdomains.txt"),
        }

        # ---------------------------------------------------------------
        # Phase 2: HTTP Probing
        # ---------------------------------------------------------------
        logger.info(f"[2/7] HTTP probing {len(subdomains)} hosts...")
        t = time.time()

        live_data = self.httpx.probe_hosts(subdomains, threads=50, timeout=10)
        live_urls = [h["url"] for h in live_data if h.get("url")]

        _write_json(out_dir / "02_live_hosts.json", live_data)
        results.phases["http_probing"] = {
            "duration_s": round(time.time() - t, 1),
            "probed": len(subdomains),
            "live": len(live_urls),
            "file": str(out_dir / "02_live_hosts.json"),
        }
        logger.info(f"  httpx → {len(live_urls)} live hosts")

        if not live_urls:
            logger.warning("No live hosts — stopping chain early")
            results.summary = _make_summary(results.phases)
            _write_json(out_dir / "chain_results.json", results.to_dict())
            return results.to_dict()

        # ---------------------------------------------------------------
        # Phase 3: Crawling
        # ---------------------------------------------------------------
        crawled_urls: List[str] = list(live_urls)  # seed with probed URLs

        if run_katana:
            logger.info(f"[3/7] Crawling {len(live_urls)} live hosts with katana (depth={crawl_depth})...")
            t = time.time()

            if self.katana.is_installed():
                endpoints = self.katana.crawl(
                    live_urls,
                    depth=crawl_depth,
                    js_crawl=True,
                    timeout=400,
                    concurrency=10,
                    rate_limit=150,
                )
                # Merge with live_urls, deduplicate
                all_endpoints = list(dict.fromkeys(live_urls + endpoints))
                crawled_urls = all_endpoints
                _write_lines(out_dir / "03_endpoints.txt", crawled_urls)
                results.phases["crawling"] = {
                    "duration_s": round(time.time() - t, 1),
                    "seed_urls": len(live_urls),
                    "endpoints_found": len(endpoints),
                    "total_unique": len(crawled_urls),
                    "file": str(out_dir / "03_endpoints.txt"),
                }
                logger.info(f"  katana → {len(endpoints)} new endpoints ({len(crawled_urls)} total)")
            else:
                logger.warning("  katana not installed — using live_urls only")
                results.phases["crawling"] = {"skipped": "katana_not_installed"}
        else:
            results.phases["crawling"] = {"skipped": "disabled"}

        # ---------------------------------------------------------------
        # Phase 4: Pattern Filtering (gf)
        # ---------------------------------------------------------------
        logger.info(f"[4/7] Filtering {len(crawled_urls)} endpoints with gf patterns...")
        t = time.time()

        patterns_to_run = ["idor", "ssrf", "xss", "sqli", "redirect", "lfi", "rce", "debug"]
        pattern_hits: Dict[str, List[str]] = {}

        for pat in patterns_to_run:
            hits = self.gf.filter_urls(crawled_urls, pat)
            pattern_hits[pat] = hits
            if hits:
                logger.info(f"  gf {pat:10s} → {len(hits)} URLs")

        _write_json(out_dir / "04_gf_patterns.json", pattern_hits)
        results.phases["gf_patterns"] = {
            "duration_s": round(time.time() - t, 1),
            "total_endpoints": len(crawled_urls),
            "hits_by_pattern": {p: len(v) for p, v in pattern_hits.items()},
            "file": str(out_dir / "04_gf_patterns.json"),
        }

        # ---------------------------------------------------------------
        # Phase 5: IDOR Fuzzing (ffuf)
        # ---------------------------------------------------------------
        if run_ffuf:
            idor_candidates = pattern_hits.get("idor", [])
            logger.info(f"[5/7] IDOR fuzzing {len(idor_candidates)} candidates with ffuf...")
            t = time.time()

            if self.ffuf.is_installed() and idor_candidates:
                import re
                idor_findings: List[Dict[str, Any]] = []

                for url in idor_candidates[:30]:  # cap at 30 URLs to avoid runtime explosion
                    # Replace the first numeric ID parameter value with FUZZ
                    fuzz_url = re.sub(
                        r'((?:id|user_?id|account_?id|doc_?id|file_?id|order_?id)=)\d+',
                        r'\1FUZZ',
                        url,
                        count=1,
                        flags=re.IGNORECASE,
                    )
                    if "FUZZ" not in fuzz_url:
                        # Fallback: replace any trailing numeric path segment
                        fuzz_url = re.sub(r'/(\d+)(/|$)', r'/FUZZ\2', url, count=1)

                    if "FUZZ" not in fuzz_url:
                        continue

                    hits = self.ffuf.fuzz_ids(
                        url_template=fuzz_url,
                        wordlist=id_wl,
                        match_codes=[200],
                        filter_codes=[404],
                        threads=ffuf_threads,
                        rate=ffuf_rate,
                        timeout=120,
                    )
                    for h in hits:
                        h["template_url"] = fuzz_url
                        h["original_url"] = url
                    idor_findings.extend(hits)

                _write_json(out_dir / "05_idor_ffuf.json", idor_findings)
                results.phases["idor_fuzzing"] = {
                    "duration_s": round(time.time() - t, 1),
                    "candidates": len(idor_candidates),
                    "fuzzed": min(len(idor_candidates), 30),
                    "findings": len(idor_findings),
                    "file": str(out_dir / "05_idor_ffuf.json"),
                }
                logger.info(f"  ffuf IDOR → {len(idor_findings)} potential IDOR hits")

            elif not self.ffuf.is_installed():
                logger.warning("  ffuf not installed — skipping IDOR fuzzing")
                results.phases["idor_fuzzing"] = {"skipped": "ffuf_not_installed"}
            else:
                logger.info("  No IDOR candidates found — skipping ffuf")
                results.phases["idor_fuzzing"] = {"skipped": "no_candidates"}
        else:
            results.phases["idor_fuzzing"] = {"skipped": "disabled"}

        # ---------------------------------------------------------------
        # Phase 6: XSS Scanning (dalfox)
        # ---------------------------------------------------------------
        if run_dalfox:
            xss_candidates = pattern_hits.get("xss", [])
            logger.info(f"[6/7] XSS scanning {len(xss_candidates)} candidates with dalfox...")
            t = time.time()

            if self.dalfox.is_installed() and xss_candidates:
                xss_findings = self.dalfox.scan_pipe(
                    xss_candidates[:50],  # cap at 50
                    blind_xss_url=blind_xss_url,
                    timeout=300,
                )
                _write_json(out_dir / "06_xss_dalfox.json", xss_findings)
                results.phases["xss_scanning"] = {
                    "duration_s": round(time.time() - t, 1),
                    "candidates": len(xss_candidates),
                    "scanned": min(len(xss_candidates), 50),
                    "findings": len(xss_findings),
                    "file": str(out_dir / "06_xss_dalfox.json"),
                }
                logger.info(f"  dalfox XSS → {len(xss_findings)} confirmed findings")

            elif not self.dalfox.is_installed():
                logger.warning("  dalfox not installed — skipping XSS scanning")
                results.phases["xss_scanning"] = {"skipped": "dalfox_not_installed"}
            else:
                logger.info("  No XSS candidates — skipping dalfox")
                results.phases["xss_scanning"] = {"skipped": "no_candidates"}
        else:
            results.phases["xss_scanning"] = {"skipped": "disabled"}

        # ---------------------------------------------------------------
        # Phase 7: Nuclei
        # ---------------------------------------------------------------
        if run_nuclei:
            logger.info(f"[7/7] Nuclei scanning {len(live_urls)} hosts...")
            t = time.time()

            if self.nuclei.is_installed():
                nuclei_findings = self.nuclei.scan_targets(
                    live_urls,
                    severity=nuclei_severity,
                    timeout=600,
                )
                _write_json(out_dir / "07_nuclei.json", nuclei_findings)
                results.phases["nuclei"] = {
                    "duration_s": round(time.time() - t, 1),
                    "hosts_scanned": len(live_urls),
                    "findings": len(nuclei_findings),
                    "by_severity": _count_by_severity(nuclei_findings),
                    "file": str(out_dir / "07_nuclei.json"),
                }
                logger.info(f"  nuclei → {len(nuclei_findings)} findings")
            else:
                logger.warning("  nuclei not installed — skipping")
                results.phases["nuclei"] = {"skipped": "nuclei_not_installed"}
        else:
            results.phases["nuclei"] = {"skipped": "disabled"}

        # ---------------------------------------------------------------
        # Summary
        # ---------------------------------------------------------------
        elapsed = round(time.time() - start, 1)
        results.summary = _make_summary(results.phases)
        results.summary["total_duration_s"] = elapsed

        _write_json(out_dir / "chain_results.json", results.to_dict())

        logger.info(
            f"=== WorkflowChain complete for {domain} in {elapsed}s — "
            f"output: {out_dir} ==="
        )
        _print_summary(domain, results)

        return results.to_dict()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_lines(path: Path, lines: List[str]) -> None:
    path.write_text("\n".join(lines))


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, default=str))


def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _make_summary(phases: Dict[str, Any]) -> Dict[str, int]:
    summary: Dict[str, int] = {}

    def _get(phase: str, key: str) -> int:
        p = phases.get(phase, {})
        return p.get(key, 0) if isinstance(p, dict) else 0

    summary["subdomains"] = _get("subdomain_enumeration", "count")
    summary["live_hosts"] = _get("http_probing", "live")
    summary["endpoints_crawled"] = _get("crawling", "total_unique")
    summary["idor_findings"] = _get("idor_fuzzing", "findings")
    summary["xss_findings"] = _get("xss_scanning", "findings")
    summary["nuclei_findings"] = _get("nuclei", "findings")
    return summary


def _print_summary(domain: str, results: ChainResults) -> None:
    s = results.summary
    print("\n" + "=" * 60)
    print(f"  WORKFLOW CHAIN SUMMARY — {domain}")
    print("=" * 60)
    print(f"  Subdomains discovered : {s.get('subdomains', 0)}")
    print(f"  Live hosts            : {s.get('live_hosts', 0)}")
    print(f"  Endpoints crawled     : {s.get('endpoints_crawled', 0)}")
    print(f"  IDOR findings (ffuf)  : {s.get('idor_findings', 0)}")
    print(f"  XSS findings (dalfox) : {s.get('xss_findings', 0)}")
    print(f"  Nuclei findings       : {s.get('nuclei_findings', 0)}")
    print(f"  Total time            : {s.get('total_duration_s', 0)}s")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="Full Bug Bounty Workflow Chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m tools.workflow_chain example.com
  python -m tools.workflow_chain example.com --output results/ --depth 5
  python -m tools.workflow_chain example.com --severity high critical --blind https://your.burp.collab
  python -m tools.workflow_chain example.com --no-nuclei --no-amass
""",
    )
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--output", "-o", default="chain_output", help="Output directory")
    parser.add_argument("--depth", "-d", type=int, default=3, help="Katana crawl depth")
    parser.add_argument("--wordlist", "-w", help="Custom ID wordlist for ffuf IDOR fuzzing")
    parser.add_argument("--severity", nargs="+", metavar="SEV", help="Nuclei severity filter")
    parser.add_argument("--blind", metavar="URL", help="Blind XSS callback URL (dalfox --blind)")
    parser.add_argument("--ffuf-threads", type=int, default=40)
    parser.add_argument("--ffuf-rate", type=int, default=100, help="Max req/s for ffuf")
    parser.add_argument("--no-amass", action="store_true", help="Skip Amass")
    parser.add_argument("--no-katana", action="store_true", help="Skip Katana crawling")
    parser.add_argument("--no-ffuf", action="store_true", help="Skip ffuf IDOR fuzzing")
    parser.add_argument("--no-dalfox", action="store_true", help="Skip dalfox XSS scanning")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip Nuclei scanning")
    parser.add_argument("--list-tools", action="store_true", help="Show tool install status and exit")

    args = parser.parse_args()

    if args.list_tools:
        print_installation_instructions()
        status = check_tool_installation()
        print("\nInstalled tools:")
        for name, ok in status.items():
            icon = "✓" if ok else "✗"
            print(f"  {icon} {name}")
        sys.exit(0)

    chain = WorkflowChain(output_dir=args.output)
    chain.run(
        domain=args.domain,
        id_wordlist=args.wordlist,
        crawl_depth=args.depth,
        ffuf_threads=args.ffuf_threads,
        ffuf_rate=args.ffuf_rate,
        nuclei_severity=args.severity,
        run_amass=not args.no_amass,
        run_katana=not args.no_katana,
        run_ffuf=not args.no_ffuf,
        run_dalfox=not args.no_dalfox,
        run_nuclei=not args.no_nuclei,
        blind_xss_url=args.blind,
    )

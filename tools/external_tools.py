"""
External tool integration wrappers for Subfinder, HTTPX, and Nuclei.
"""
import subprocess
import json
import logging
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)


class ExternalToolError(Exception):
    """Raised when external tool execution fails."""


class ExternalTool:
    """Base class for external tool wrappers."""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.binary_path = shutil.which(tool_name)

    def is_installed(self) -> bool:
        """Check if the tool is installed and available in PATH."""
        return self.binary_path is not None

    def _run_command(self, args: List[str], timeout: int = 300) -> str:
        """
        Execute tool command and return stdout.

        Args:
            args: Command arguments (tool name will be prepended)
            timeout: Command timeout in seconds

        Returns:
            Command stdout as string

        Raises:
            ExternalToolError: If command fails or times out
        """
        if not self.binary_path:
            raise ExternalToolError(
                f"{self.tool_name} is not installed. "
                f"Install with: go install -v {self._get_install_command()}"
            )

        cmd = [self.binary_path] + args
        # Filter out None values and ensure all are strings
        cmd = [str(arg) for arg in cmd if arg is not None]
        logger.info(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
                check=False
            )

            if result.returncode != 0:
                logger.warning(
                    f"{self.tool_name} exited with code {result.returncode}. "
                    f"stderr: {result.stderr[:500]}"
                )

            return result.stdout

        except subprocess.TimeoutExpired:
            raise ExternalToolError(f"{self.tool_name} command timed out after {timeout}s")
        except Exception as e:
            raise ExternalToolError(f"Failed to run {self.tool_name}: {e}")

    def _get_install_command(self) -> str:
        """Return the go install command for this tool."""
        raise NotImplementedError


class SubfinderWrapper(ExternalTool):
    """Wrapper for Subfinder subdomain enumeration tool."""

    def __init__(self):
        super().__init__("subfinder")

    def _get_install_command(self) -> str:
        return "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    def enumerate_subdomains(
        self,
        domain: str,
        silent: bool = True,
        recursive: bool = False,
        timeout: int = 60
    ) -> List[str]:
        """
        Enumerate subdomains for a given domain.

        Args:
            domain: Target domain (e.g., "example.com")
            silent: Only show subdomains in output
            recursive: Use recursive subdomain enumeration
            timeout: Command timeout in seconds (default: 60s)

        Returns:
            List of discovered subdomains
        """
        args = ["-d", domain, "-json"]

        if silent:
            args.append("-silent")
        if recursive:
            args.append("-recursive")

        # Add explicit timeout to subfinder itself (30s max per source)
        args.extend(["-timeout", "30"])

        try:
            output = self._run_command(args, timeout=timeout)

            subdomains = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    if host and host not in subdomains:
                        subdomains.append(host)
                except json.JSONDecodeError:
                    # Fallback for non-JSON output
                    if line and not line.startswith('['):
                        subdomains.append(line.strip())

            logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
            return subdomains

        except ExternalToolError as e:
            logger.error(f"Subfinder enumeration failed: {e}")
            return []


class HTTPXWrapper(ExternalTool):
    """Wrapper for HTTPX HTTP probing tool."""

    def __init__(self):
        super().__init__("httpx")

    def _get_install_command(self) -> str:
        return "github.com/projectdiscovery/httpx/cmd/httpx@latest"

    def probe_hosts(
        self,
        hosts: List[str],
        silent: bool = True,
        follow_redirects: bool = True,
        timeout: int = 10,
        threads: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Probe hosts to find live web servers.

        Args:
            hosts: List of hosts/URLs to probe
            silent: Display only results
            follow_redirects: Follow HTTP redirects
            timeout: Request timeout in seconds
            threads: Number of concurrent threads

        Returns:
            List of probe results with URL, status, title, tech, etc.
        """
        if not hosts:
            return []

        args = [
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-timeout", str(timeout),
            "-threads", str(threads)
        ]

        if silent:
            args.append("-silent")
        if follow_redirects:
            args.append("-follow-redirects")

        # Write hosts to temp file for input
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for host in hosts:
                f.write(f"{host}\n")
            temp_file = f.name

        args.extend(["-list", temp_file])

        try:
            output = self._run_command(args, timeout=len(hosts) * 2 + 60)

            results = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "content_length": data.get("content_length", 0),
                        "technologies": data.get("technologies", []),
                        "webserver": data.get("webserver", ""),
                        "host": data.get("host", ""),
                        "scheme": data.get("scheme", "https")
                    })
                except json.JSONDecodeError:
                    continue

            logger.info(f"HTTPX probed {len(hosts)} hosts, found {len(results)} live")
            return results

        except ExternalToolError as e:
            logger.error(f"HTTPX probing failed: {e}")
            return []
        finally:
            # Clean up temp file
            try:
                Path(temp_file).unlink()
            except Exception:
                pass


class NucleiWrapper(ExternalTool):
    """Wrapper for Nuclei vulnerability scanner."""

    def __init__(self):
        super().__init__("nuclei")

    def _get_install_command(self) -> str:
        return "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    def scan_targets(
        self,
        targets: List[str],
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        silent: bool = True,
        rate_limit: int = 150,
        timeout: int = 600
    ) -> List[Dict[str, Any]]:
        """
        Scan targets with Nuclei vulnerability templates.

        Args:
            targets: List of URLs to scan
            templates: Specific template paths/IDs to use
            severity: Filter by severity (info, low, medium, high, critical)
            tags: Filter by template tags
            silent: Display only results
            rate_limit: Maximum requests per second
            timeout: Command timeout in seconds

        Returns:
            List of findings with template info, severity, matched URL, etc.
        """
        if not targets:
            return []

        args = [
            "-json",
            "-rate-limit", str(rate_limit),
            "-timeout", "10"
        ]

        if silent:
            args.append("-silent")

        if templates:
            for template in templates:
                args.extend(["-t", template])
        else:
            # Use default templates
            args.extend(["-t", "~/.local/nuclei-templates/"])

        if severity:
            args.extend(["-severity", ",".join(severity)])

        if tags:
            args.extend(["-tags", ",".join(tags)])

        # Write targets to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            temp_file = f.name

        args.extend(["-list", temp_file])

        try:
            output = self._run_command(args, timeout=timeout)

            findings = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "template_id": data.get("template-id", ""),
                        "template_name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", "info"),
                        "type": data.get("type", ""),
                        "host": data.get("host", ""),
                        "matched_at": data.get("matched-at", ""),
                        "extracted_results": data.get("extracted-results", []),
                        "matcher_name": data.get("matcher-name", ""),
                        "description": data.get("info", {}).get("description", ""),
                        "reference": data.get("info", {}).get("reference", []),
                        "tags": data.get("info", {}).get("tags", []),
                        "cvss_score": data.get("info", {}).get("classification", {}).get("cvss-score", 0)
                    })
                except json.JSONDecodeError:
                    continue

            logger.info(f"Nuclei scanned {len(targets)} targets, found {len(findings)} issues")
            return findings

        except ExternalToolError as e:
            logger.error(f"Nuclei scan failed: {e}")
            return []
        finally:
            # Clean up temp file
            try:
                Path(temp_file).unlink()
            except Exception:
                pass

    def update_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        try:
            args = ["-update-templates"]
            self._run_command(args, timeout=120)
            logger.info("Nuclei templates updated successfully")
            return True
        except ExternalToolError as e:
            logger.error(f"Failed to update Nuclei templates: {e}")
            return False


class AmassWrapper(ExternalTool):
    """Wrapper for Amass subdomain enumeration tool (OWASP)."""

    def __init__(self):
        super().__init__("amass")

    def _get_install_command(self) -> str:
        return "github.com/owasp-amass/amass/v4/...@master"

    def enumerate_subdomains(
        self,
        domain: str,
        passive: bool = True,
        timeout: int = 120
    ) -> List[str]:
        """
        Enumerate subdomains using Amass.

        Args:
            domain: Target domain (e.g., "example.com")
            passive: Use passive-only enumeration (no active probing)
            timeout: Command timeout in seconds

        Returns:
            List of discovered subdomains
        """
        args = ["enum", "-d", domain]
        if passive:
            args.append("-passive")

        try:
            output = self._run_command(args, timeout=timeout)
            subdomains = []
            for line in output.strip().split('\n'):
                line = line.strip()
                if line and domain in line:
                    # Amass output can have extra info; grab only the hostname
                    parts = line.split()
                    host = parts[0] if parts else ""
                    if host and host not in subdomains:
                        subdomains.append(host)

            logger.info(f"Amass found {len(subdomains)} subdomains for {domain}")
            return subdomains
        except ExternalToolError as e:
            logger.error(f"Amass enumeration failed: {e}")
            return []


class KatanaWrapper(ExternalTool):
    """Wrapper for Katana web crawler (ProjectDiscovery)."""

    def __init__(self):
        super().__init__("katana")

    def _get_install_command(self) -> str:
        return "github.com/projectdiscovery/katana/cmd/katana@latest"

    def crawl(
        self,
        urls: List[str],
        depth: int = 3,
        js_crawl: bool = True,
        silent: bool = True,
        timeout: int = 300,
        concurrency: int = 10,
        rate_limit: int = 150
    ) -> List[str]:
        """
        Crawl URLs and discover endpoints.

        Args:
            urls: Seed URLs to crawl
            depth: Crawl depth
            js_crawl: Parse and crawl JS files for endpoints
            silent: Only print discovered URLs
            timeout: Command timeout in seconds
            concurrency: Number of concurrent crawlers
            rate_limit: Max requests per second

        Returns:
            List of discovered endpoints
        """
        if not urls:
            return []

        args = [
            "-d", str(depth),
            "-c", str(concurrency),
            "-rate-limit", str(rate_limit),
            "-timeout", "10",
        ]

        if silent:
            args.append("-silent")
        if js_crawl:
            args.append("-js-crawl")

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for url in urls:
                f.write(f"{url}\n")
            temp_file = f.name

        args.extend(["-list", temp_file])

        try:
            output = self._run_command(args, timeout=timeout)
            endpoints = [
                line.strip() for line in output.strip().split('\n')
                if line.strip() and line.startswith('http')
            ]
            logger.info(f"Katana discovered {len(endpoints)} endpoints")
            return endpoints
        except ExternalToolError as e:
            logger.error(f"Katana crawl failed: {e}")
            return []
        finally:
            try:
                Path(temp_file).unlink()
            except Exception:
                pass


class FfufWrapper(ExternalTool):
    """Wrapper for ffuf fast web fuzzer."""

    def __init__(self):
        super().__init__("ffuf")

    def _get_install_command(self) -> str:
        return "github.com/ffuf/ffuf/v2@latest"

    def fuzz_ids(
        self,
        url_template: str,
        wordlist: str,
        match_codes: Optional[List[int]] = None,
        filter_codes: Optional[List[int]] = None,
        threads: int = 40,
        timeout: int = 300,
        rate: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Fuzz a URL containing FUZZ keyword (IDOR/parameter fuzzing).

        Args:
            url_template: URL with FUZZ placeholder, e.g. /api/user?id=FUZZ
            wordlist: Path to wordlist file
            match_codes: HTTP status codes to match (default: [200])
            filter_codes: HTTP status codes to filter out
            threads: Number of threads
            timeout: Command timeout in seconds
            rate: Max requests/second (0 = unlimited)

        Returns:
            List of matching results with url, status, length, words, lines
        """
        if match_codes is None:
            match_codes = [200]

        args = [
            "-u", url_template,
            "-w", wordlist,
            "-mc", ",".join(str(c) for c in match_codes),
            "-t", str(threads),
            "-json",
            "-s",  # silent mode
        ]

        if filter_codes:
            args.extend(["-fc", ",".join(str(c) for c in filter_codes)])

        if rate > 0:
            args.extend(["-rate", str(rate)])

        try:
            output = self._run_command(args, timeout=timeout)
            results = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", ""),
                        "status": data.get("status", 0),
                        "length": data.get("length", 0),
                        "words": data.get("words", 0),
                        "lines": data.get("lines", 0),
                        "input": data.get("input", {}).get("FUZZ", ""),
                        "redirect_location": data.get("redirectlocation", ""),
                    })
                except json.JSONDecodeError:
                    continue

            logger.info(f"ffuf found {len(results)} matches for {url_template}")
            return results
        except ExternalToolError as e:
            logger.error(f"ffuf fuzzing failed: {e}")
            return []

    def fuzz_dirs(
        self,
        base_url: str,
        wordlist: str,
        extensions: Optional[List[str]] = None,
        match_codes: Optional[List[int]] = None,
        threads: int = 40,
        timeout: int = 300
    ) -> List[Dict[str, Any]]:
        """Directory/path fuzzing."""
        url_template = base_url.rstrip('/') + "/FUZZ"
        if extensions:
            # ffuf -e flag for extensions
            extra_args = ["-e", ",".join(ext if ext.startswith('.') else f".{ext}" for ext in extensions)]
        else:
            extra_args = []

        if match_codes is None:
            match_codes = [200, 201, 204, 301, 302, 307, 401, 403]

        args = [
            "-u", url_template,
            "-w", wordlist,
            "-mc", ",".join(str(c) for c in match_codes),
            "-t", str(threads),
            "-json",
            "-s",
        ] + extra_args

        try:
            output = self._run_command(args, timeout=timeout)
            results = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", ""),
                        "status": data.get("status", 0),
                        "length": data.get("length", 0),
                        "input": data.get("input", {}).get("FUZZ", ""),
                    })
                except json.JSONDecodeError:
                    continue
            return results
        except ExternalToolError as e:
            logger.error(f"ffuf dir fuzzing failed: {e}")
            return []


class GfWrapper(ExternalTool):
    """Wrapper for gf (grep patterns for bug bounty)."""

    def __init__(self):
        super().__init__("gf")

    def _get_install_command(self) -> str:
        return "github.com/tomnomnom/gf@latest"

    # Built-in patterns for environments where gf is not installed
    _BUILTIN_PATTERNS: Dict[str, List[str]] = {
        "idor": [r"[?&](id|user_?id|account_?id|doc_?id|file_?id|order_?id)=\d+"],
        "ssrf": [r"[?&](url|uri|path|dest|destination|redirect|next|target|src|source|host|endpoint|proxy|fetch|load|open)="],
        "xss": [r"[?&](q|query|search|s|term|keyword|name|title|msg|message|content|text|comment|input|data)="],
        "sqli": [r"[?&](id|cat|num|page|type|sort|order|by|key|keyword|search|query|filter)=\d+"],
        "redirect": [r"[?&](redirect|return|next|url|dest|destination|redir|go|r|link|forward)="],
        "lfi": [r"[?&](file|filename|path|include|page|doc|document|folder|root|dir|content|load|template)="],
        "rce": [r"[?&](cmd|exec|command|run|shell|code|eval|system|ping|host|target)="],
        "debug": [r"[?&](debug|test|dev|trace|verbose|api_?key|token|secret|password)="],
    }

    def filter_urls(
        self,
        urls: List[str],
        pattern: str
    ) -> List[str]:
        """
        Filter URLs using a gf pattern.

        Falls back to built-in regex patterns if gf is not installed.

        Args:
            urls: List of URLs to filter
            pattern: Pattern name (e.g., "idor", "ssrf", "xss", "sqli")

        Returns:
            Filtered list of matching URLs
        """
        if not urls:
            return []

        # Try gf binary first
        if self.is_installed():
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(urls))
                temp_file = f.name
            try:
                output = self._run_command([pattern], timeout=30)
                # gf reads from stdin when no file given; use subprocess directly
                import subprocess
                proc = subprocess.run(
                    [self.binary_path, pattern],
                    input='\n'.join(urls),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30
                )
                matched = [l.strip() for l in proc.stdout.strip().split('\n') if l.strip()]
                logger.info(f"gf '{pattern}' matched {len(matched)}/{len(urls)} URLs")
                return matched
            except Exception as e:
                logger.warning(f"gf binary failed ({e}), using built-in patterns")
            finally:
                try:
                    Path(temp_file).unlink()
                except Exception:
                    pass

        # Fallback: built-in regex patterns
        import re as _re
        regexes = self._BUILTIN_PATTERNS.get(pattern, [])
        if not regexes:
            logger.warning(f"No built-in pattern for '{pattern}'; returning all URLs")
            return urls

        matched = []
        for url in urls:
            if any(_re.search(rx, url, _re.IGNORECASE) for rx in regexes):
                matched.append(url)

        logger.info(f"Built-in gf '{pattern}' matched {len(matched)}/{len(urls)} URLs")
        return matched


class DalfoxWrapper(ExternalTool):
    """Wrapper for dalfox automated XSS scanner."""

    def __init__(self):
        super().__init__("dalfox")

    def _get_install_command(self) -> str:
        return "github.com/hahwul/dalfox/v2@latest"

    def scan_url(
        self,
        url: str,
        blind_xss_url: Optional[str] = None,
        skip_bav: bool = True,
        timeout: int = 120,
        worker: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Scan a single URL for XSS vulnerabilities.

        Args:
            url: Target URL to scan
            blind_xss_url: Callback URL for blind XSS detection
            skip_bav: Skip BAV (Bad-Actor Validation) payloads
            timeout: Command timeout in seconds
            worker: Number of concurrent workers

        Returns:
            List of XSS findings
        """
        args = ["url", url, "--format", "json", "--silence", "--worker", str(worker)]
        if blind_xss_url:
            args.extend(["--blind", blind_xss_url])
        if skip_bav:
            args.append("--skip-bav")

        try:
            output = self._run_command(args, timeout=timeout)
            findings = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("type") in ("G", "R", "V"):  # GET/reflected/verified
                        findings.append({
                            "url": data.get("data", url),
                            "param": data.get("param", ""),
                            "payload": data.get("payload", ""),
                            "type": data.get("type", ""),
                            "evidence": data.get("evidence", ""),
                            "severity": "high" if data.get("type") == "V" else "medium",
                        })
                except json.JSONDecodeError:
                    continue

            logger.info(f"dalfox found {len(findings)} XSS issues in {url}")
            return findings
        except ExternalToolError as e:
            logger.error(f"dalfox scan failed: {e}")
            return []

    def scan_pipe(
        self,
        urls: List[str],
        blind_xss_url: Optional[str] = None,
        timeout: int = 300,
        worker: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Scan multiple URLs (pipe mode) for XSS.

        Args:
            urls: List of URLs to scan
            blind_xss_url: Callback URL for blind XSS detection
            timeout: Command timeout in seconds
            worker: Concurrent workers

        Returns:
            Aggregated list of XSS findings
        """
        if not urls:
            return []

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(urls))
            temp_file = f.name

        args = ["file", temp_file, "--format", "json", "--silence", "--worker", str(worker)]
        if blind_xss_url:
            args.extend(["--blind", blind_xss_url])

        try:
            output = self._run_command(args, timeout=timeout)
            findings = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("type") in ("G", "R", "V"):
                        findings.append({
                            "url": data.get("data", ""),
                            "param": data.get("param", ""),
                            "payload": data.get("payload", ""),
                            "type": data.get("type", ""),
                            "evidence": data.get("evidence", ""),
                            "severity": "high" if data.get("type") == "V" else "medium",
                        })
                except json.JSONDecodeError:
                    continue

            logger.info(f"dalfox pipe found {len(findings)} XSS issues across {len(urls)} URLs")
            return findings
        except ExternalToolError as e:
            logger.error(f"dalfox pipe scan failed: {e}")
            return []
        finally:
            try:
                Path(temp_file).unlink()
            except Exception:
                pass


def check_tool_installation() -> Dict[str, bool]:
    """
    Check which external tools are installed.

    Returns:
        Dictionary mapping tool name to installation status
    """
    tools = {
        "subfinder": SubfinderWrapper(),
        "amass": AmassWrapper(),
        "httpx": HTTPXWrapper(),
        "katana": KatanaWrapper(),
        "ffuf": FfufWrapper(),
        "gf": GfWrapper(),
        "dalfox": DalfoxWrapper(),
        "nuclei": NucleiWrapper(),
    }

    status = {}
    for name, tool in tools.items():
        installed = tool.is_installed()
        status[name] = installed
        if installed:
            logger.info(f"✓ {name} is installed at {tool.binary_path}")
        else:
            logger.warning(
                f"✗ {name} is not installed. "
                f"Install with: go install -v {tool._get_install_command()}"
            )

    return status


def print_installation_instructions():
    """Print installation instructions for missing tools."""
    print("\n" + "="*70)
    print("EXTERNAL TOOL INSTALLATION INSTRUCTIONS")
    print("="*70)
    print("\nAll tools require Go to be installed: https://go.dev/doc/install")
    print("\nInstall all tools with these commands:\n")

    tools = [
        ("Subfinder (subdomain enum)", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("Amass (subdomain enum)", "github.com/owasp-amass/amass/v4/...@master"),
        ("HTTPX (HTTP probing)", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("Katana (web crawling)", "github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("ffuf (fuzzing)", "github.com/ffuf/ffuf/v2@latest"),
        ("gf (grep patterns)", "github.com/tomnomnom/gf@latest"),
        ("dalfox (XSS scanner)", "github.com/hahwul/dalfox/v2@latest"),
        ("Nuclei (vuln scanner)", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ]

    for name, path in tools:
        print(f"# {name}")
        print(f"go install -v {path}\n")

    print("After installation, update Nuclei templates:")
    print("nuclei -update-templates\n")
    print("Install gf patterns:")
    print("mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf\n")
    print("="*70 + "\n")

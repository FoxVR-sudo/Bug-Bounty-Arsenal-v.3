"""
Command Injection Detector
Detects OS command injection vulnerabilities using time-based and output-based techniques.

Reward potential: $2000-10000+
"""

from detectors.registry import register_active
import asyncio
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import hashlib


@register_active
async def command_injection_detector(session, url, context):
    """
    Detect OS command injection vulnerabilities.

    Uses both time-based (sleep) and output-based detection methods.
    Tests various command injection contexts (shell, pipes, backticks, etc.)

    Args:
        session: aiohttp ClientSession
        url: Target URL to test
        context: Scanner context/configuration

    Returns:
        List of findings
    """
    findings = []

    # Parse URL
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    # ── Baseline timing measurement ────────────────────────────────────────────
    # Measure how long the server normally takes to respond so that time-based
    # detection uses a *relative* threshold instead of a fixed 4.5-6.5s window.
    # A server that already takes 3+ seconds cannot reliably be tested by timing.
    _timeout = context.get('timeout', 15) if context else 15
    _baseline_samples = []
    for _ in range(2):
        _t0 = time.time()
        try:
            async with session.get(url, allow_redirects=False, timeout=_timeout) as _r:
                await _r.read()
        except Exception:
            pass
        _baseline_samples.append(time.time() - _t0)

    _baseline_time = sum(_baseline_samples) / len(_baseline_samples) if _baseline_samples else 0.5
    # If the server is naturally slow, time-based detection would produce too many FPs
    _skip_time_based = _baseline_time > 3.0

    # Dynamic thresholds: baseline + sleep(5) should land in this window
    _time_low  = _baseline_time + 3.5
    _time_high = _baseline_time + 7.0
    # ──────────────────────────────────────────────────────────────────────────

    # Time-based payloads (sleep detection)
    time_based_payloads = {
        'unix_semicolon': '; sleep 5',
        'unix_pipe': '| sleep 5',
        'unix_and': '&& sleep 5',
        'unix_or': '|| sleep 5',
        'unix_backtick': '`sleep 5`',
        'unix_dollar': '$(sleep 5)',
        'unix_newline': '\nsleep 5',
        'windows_and': '& timeout 5',
        'windows_pipe': '| timeout 5',
    }

    # Output-based payloads (command execution detection)
    output_payloads = {
        'unix_whoami': '; whoami',
        'unix_id': '| id',
        'unix_pwd': '`pwd`',
        'unix_uname': '$(uname -a)',
        'windows_whoami': '& whoami',
        'windows_ver': '| ver',
    }

    for param_name, param_values in params.items():
        original_value = param_values[0] if param_values else ''

        # Test time-based payloads
        for payload_name, payload in time_based_payloads.items():
            if _skip_time_based:
                break  # Server too slow for reliable time-based detection
            test_params = params.copy()
            test_params[param_name] = [original_value + payload]

            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(test_params, doseq=True),
                parsed.fragment
            ))

            start_time = time.time()
            try:
                async with session.get(
                    test_url,
                    timeout=context.get('timeout', 15) if context else 15,
                    allow_redirects=False
                ) as resp:
                    response_text = await resp.text()
                    elapsed = time.time() - start_time

                    # Dynamic window: baseline + sleep(5) should trigger this
                    if _time_low <= elapsed <= _time_high:
                        evidence_id = hashlib.md5(test_url.encode()).hexdigest()[:12]

                        findings.append({
                            'type': 'Command Injection (Time-Based)',
                            'severity': 'critical',
                            'confidence': 'high',
                            'url': test_url,
                            'method': 'GET',
                            'vulnerable_parameter': param_name,
                            'parameter_location': 'query',
                            'payload': payload,
                            'payload_type': payload_name,
                            'evidence': f'Response delayed by {elapsed:.2f}s (baseline: {_baseline_time:.2f}s, threshold: {_time_low:.1f}-{_time_high:.1f}s), indicating command execution.',
                            'evidence_id': evidence_id,
                            'impact': 'Critical: Attacker can execute arbitrary OS commands on the server, leading to complete system compromise, data theft, malware installation, or using the server for further attacks.',
                            'recommendation': '1. Never pass user input directly to shell commands\n2. Use parameterized APIs instead of shell commands\n3. Implement strict input validation (whitelist approach)\n4. Escape shell metacharacters if shell execution is unavoidable\n5. Run application with minimal privileges\n6. Use sandboxing or containerization',
                            'repro_command': f'curl -X GET "{test_url}" -w "\\nTime: %{{time_total}}s\\n"',
                            'cvss_score': 9.8,
                            'cwe': 'CWE-78',
                            'owasp': 'A03:2021 - Injection'
                        })

                        # Don't test more payloads for this parameter
                        break

            except asyncio.TimeoutError:
                # Timeout might also indicate command execution
                elapsed = time.time() - start_time
                if elapsed >= (context.get('timeout', 15) if context else 15) - 1:
                    evidence_id = hashlib.md5(test_url.encode()).hexdigest()[:12]

                    findings.append({
                        'type': 'Command Injection (Time-Based - Timeout)',
                        'severity': 'high',
                        'confidence': 'medium',
                        'url': test_url,
                        'method': 'GET',
                        'vulnerable_parameter': param_name,
                        'parameter_location': 'query',
                        'payload': payload,
                        'payload_type': payload_name,
                        'evidence': f'Request timed out after {elapsed:.2f} seconds, potentially indicating command execution.',
                        'evidence_id': evidence_id,
                        'impact': 'High: Possible OS command injection. Requires manual verification.',
                        'recommendation': 'Manually verify if command injection is possible. Implement input validation and avoid shell command execution.',
                        'repro_command': f'curl -X GET "{test_url}" -w "\\nTime: %{{time_total}}s\\n" --max-time 20',
                        'cvss_score': 8.5,
                        'cwe': 'CWE-78',
                        'owasp': 'A03:2021 - Injection'
                    })
                    break

            except Exception:
                # Silently continue on other errors
                continue

        # Test output-based payloads (look for command output in response)
        for payload_name, payload in output_payloads.items():
            test_params = params.copy()
            test_params[param_name] = [original_value + payload]

            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(test_params, doseq=True),
                parsed.fragment
            ))

            try:
                async with session.get(
                    test_url,
                    timeout=context.get('timeout', 15) if context else 15,
                    allow_redirects=False
                ) as resp:
                    response_text = await resp.text()
                    response_lower = response_text.lower()

                    # Look for typical command output patterns
                    command_indicators = [
                        'uid=', 'gid=',  # id command
                        'root:', '/bin/', '/usr/',  # whoami, pwd
                        'linux', 'darwin', 'windows',  # uname, ver
                        'microsoft windows', 'version',  # ver command
                    ]

                    found_indicators = [ind for ind in command_indicators if ind in response_lower]

                    if found_indicators:
                        evidence_id = hashlib.md5(test_url.encode()).hexdigest()[:12]

                        # Extract relevant portion of response
                        evidence_snippet = response_text[:500] if len(response_text) > 500 else response_text

                        findings.append({
                            'type': 'Command Injection (Output-Based)',
                            'severity': 'critical',
                            'confidence': 'high',
                            'url': test_url,
                            'method': 'GET',
                            'vulnerable_parameter': param_name,
                            'parameter_location': 'query',
                            'payload': payload,
                            'payload_type': payload_name,
                            'evidence': f'Command output detected in response. Found indicators: {", ".join(found_indicators)}. Response snippet: {evidence_snippet}',
                            'evidence_id': evidence_id,
                            'impact': 'Critical: Command injection confirmed. Attacker can execute arbitrary OS commands.',
                            'recommendation': '1. Immediate: Disable or restrict the vulnerable endpoint\n2. Implement strict input validation\n3. Never use shell execution with user input\n4. Use secure APIs instead of shell commands\n5. Apply principle of least privilege',
                            'repro_command': f'curl -X GET "{test_url}"',
                            'cvss_score': 10.0,
                            'cwe': 'CWE-78',
                            'owasp': 'A03:2021 - Injection'
                        })

                        # Found confirmed command injection, stop testing this parameter
                        break

            except Exception:
                continue

    return findings

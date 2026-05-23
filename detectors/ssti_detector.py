"""
SSTI (Server-Side Template Injection) Vulnerability Detector
Detects Server-Side Template Injection vulnerabilities
Reward potential: $2000-8000+

Detection techniques:
- Mathematical expression evaluation ({{7*7}}, ${7*7}, etc.)
- Template-specific syntax testing (Jinja2, Twig, Freemarker, Velocity, Smarty, etc.)
- Context-aware payload generation
- Polyglot payloads for multiple template engines
- Error-based detection

CWE: CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
OWASP: A03:2021 - Injection
"""

import asyncio
import re
from .registry import register_active

# Template engine detection payloads
# Format: {template_engine: [{payload: expected_result}]}
SSTI_PAYLOADS = {
    'jinja2': [
        {'payload': '{{7*7}}', 'expected': '49', 'description': 'Basic math'},
        {'payload': '{{7*\'7\'}}', 'expected': '7777777', 'description': 'String multiplication'},
        {'payload': '{{config}}', 'expected': 'Config', 'description': 'Config object access'},
        {'payload': '{{config.items()}}', 'expected': 'dict_items', 'description': 'Config items'},
        {'payload': '{{request}}', 'expected': 'Request', 'description': 'Request object'},
        {'payload': '{{self}}', 'expected': 'TemplateReference', 'description': 'Template reference'},
    ],

    'twig': [
        {'payload': '{{7*7}}', 'expected': '49', 'description': 'Basic math'},
        {'payload': '{{7*\'7\'}}', 'expected': '7777777', 'description': 'String multiplication'},
        {'payload': '{{\"7\"*7}}', 'expected': '7777777', 'description': 'String multiplication alt'},
        {'payload': '{{_self}}', 'expected': '__TwigTemplate_', 'description': 'Template object'},
    ],

    'freemarker': [
        {'payload': '${7*7}', 'expected': '49', 'description': 'Basic math'},
        {'payload': '${7*\'7\'}', 'expected': '7777777', 'description': 'String multiplication'},
        {'payload': '${7+7}', 'expected': '14', 'description': 'Addition'},
        {'payload': '${3*3}${3*3}', 'expected': '99', 'description': 'Multiple expressions'},
    ],

    'velocity': [
        {'payload': '#set($x=7*7)$x', 'expected': '49', 'description': 'Variable assignment'},
        {'payload': '#set($x=7)#set($y=7)$x*$y', 'expected': '49', 'description': 'Math operation'},
        {'payload': '$class.inspect("java.lang.Runtime")', 'expected': 'java.lang.Runtime', 'description': 'Class inspection'},
    ],

    'smarty': [
        {'payload': '{$smarty.version}', 'expected': 'Smarty-', 'description': 'Smarty version'},
        {'payload': '{7*7}', 'expected': '49', 'description': 'Basic math'},
        {'payload': '{php}echo 7*7;{/php}', 'expected': '49', 'description': 'PHP code execution'},
    ],

    'mako': [
        {'payload': '${7*7}', 'expected': '49', 'description': 'Basic math'},
        {'payload': '<%=7*7%>', 'expected': '49', 'description': 'Expression tag'},
    ],

    'erb': [
        {'payload': '<%=7*7%>', 'expected': '49', 'description': 'Basic math'},
        {'payload': '<%=7*"7"%>', 'expected': '7777777', 'description': 'String multiplication'},
    ],

    'django': [
        {'payload': '{{7|add:"7"}}', 'expected': '14', 'description': 'Add filter'},
        {'payload': '{{request}}', 'expected': 'WSGIRequest', 'description': 'Request object'},
    ],

    'tornado': [
        {'payload': '{{7*7}}', 'expected': '49', 'description': 'Basic math'},
        {'payload': '{{7*\'7\'}}', 'expected': '7777777', 'description': 'String multiplication'},
    ],
}

# Polyglot payloads that work across multiple template engines
POLYGLOT_PAYLOADS = [
    {'payload': '{{7*7}}${7*7}<%=7*7%>', 'expected_patterns': ['49'], 'description': 'Math polyglot'},
    {'payload': '{{7*\'7\'}}${7*\'7\'}', 'expected_patterns': ['7777777'], 'description': 'String multiplication polyglot'},
    {'payload': '${{7*7}}', 'expected_patterns': ['49'], 'description': 'Nested expression'},
    {'payload': 'a{{bar}}b', 'expected_patterns': ['abarb', 'a.*b'], 'description': 'Variable interpolation'},
]

# Error-based detection patterns
SSTI_ERROR_INDICATORS = [
    'jinja2.exceptions',
    'TemplateSyntaxError',
    'UndefinedError',
    'TemplateNotFound',
    'TemplateError',
    'TemplateRuntimeError',
    'freemarker.core',
    'ParseException',
    'TemplateException',
    'EvaluationException',
    'Template parsing error',
    'smarty error',
    'Twig_Error',
    'Unclosed tag',
    'Unexpected token',
]


def detect_ssti_in_response(response_text, expected_value):
    """Check if response contains expected SSTI evaluation result"""
    if not expected_value:
        return False

    # Direct match
    if expected_value in response_text:
        return True

    # Regex pattern match (for flexible matching)
    try:
        if re.search(expected_value, response_text, re.IGNORECASE):
            return True
    except re.error:
        pass

    return False


def detect_ssti_error(response_text):
    """Detect template engine error messages"""
    for indicator in SSTI_ERROR_INDICATORS:
        if indicator.lower() in response_text.lower():
            return True
    return False


def extract_context(response_text, search_string, context_length=50):
    """Extract context around a matched string"""
    idx = response_text.lower().find(search_string.lower())
    if idx == -1:
        return None

    start = max(0, idx - context_length)
    end = min(len(response_text), idx + len(search_string) + context_length)

    return response_text[start:end]


@register_active
async def ssti_detector(session, url, context):
    """
    Detect SSTI (Server-Side Template Injection) vulnerabilities

    Tests multiple template engines:
    - Jinja2 (Python/Flask)
    - Twig (PHP)
    - Freemarker (Java)
    - Velocity (Java)
    - Smarty (PHP)
    - Mako (Python)
    - ERB (Ruby)
    - Django (Python)
    - Tornado (Python)

    Detection methods:
    1. Mathematical expression evaluation
    2. String manipulation tests
    3. Template object access
    4. Polyglot payloads
    5. Error-based detection

    Returns list of SSTI vulnerability findings
    """
    findings = []

    try:
        # Get baseline response
        baseline_response = await session.get(url, allow_redirects=False, timeout=8)
        baseline_text = await baseline_response.text()
        baseline_status = baseline_response.status
        len(baseline_text)

        # Parse URL to inject payloads into query parameters
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)

        # If URL has query parameters, test them
        query_params = parse_qs(parsed.query)

        if not query_params:
            # Try adding a test parameter
            query_params = {'test': ['value']}

        # Test each template engine
        for engine_name, payloads in SSTI_PAYLOADS.items():
            for payload_info in payloads[:3]:  # Test first 3 payloads per engine
                payload = payload_info['payload']
                expected = payload_info['expected']
                description = payload_info['description']

                # Test each query parameter
                for param_name, param_values in list(query_params.items()):
                    # Replace parameter value with payload
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]

                    # Build test URL
                    test_query = urlencode(test_params, doseq=True)
                    test_parsed = parsed._replace(query=test_query)
                    test_url = urlunparse(test_parsed)

                    try:
                        response = await session.get(test_url, allow_redirects=False, timeout=8)
                        response_text = await response.text()

                        # Check if expected result appears in response
                        if detect_ssti_in_response(response_text, expected):
                            # Skip if the expected value already appears in the baseline
                            # (it pre-exists on the page, not injected by us)
                            if detect_ssti_in_response(baseline_text, expected):
                                continue

                            # Extract context around the match (use distinct var name to avoid
                            # shadowing the `context` detector parameter)
                            ctx_snippet = extract_context(response_text, expected)

                            findings.append({
                                'type': f'SSTI - {engine_name.upper()}',
                                'severity': 'critical',
                                'confidence': 'high',
                                'url': url,
                                'method': 'GET',
                                'vulnerable_parameter': param_name,
                                'evidence': f'Server-Side Template Injection detected! Template engine: {engine_name}. Payload "{payload}" ({description}) was evaluated and returned expected result "{expected}". Context: ...{ctx_snippet}...',
                                'payload': payload,
                                'expected_result': expected,
                                'template_engine': engine_name,
                                'test_description': description,
                                'response_status': response.status,
                                'response_length': len(response_text),
                                'cvss_score': 9.8,
                                'cwe': 'CWE-1336',
                                'impact': f'Critical vulnerability! Attacker can execute arbitrary code on the server through {engine_name} template injection. This can lead to: Remote Code Execution (RCE), complete server compromise, data exfiltration, privilege escalation, and backdoor installation.',
                                'recommendation': '1. Never pass user input directly to template rendering functions\n2. Use template engines in "sandbox" mode if available\n3. Implement strict input validation and sanitization\n4. Use auto-escaping features of template engines\n5. Avoid dynamic template generation from user input\n6. Implement Content Security Policy (CSP)',
                                'repro_command': f'curl "{test_url}"',
                                'test_url': test_url,
                            })

                            # Found high-confidence SSTI, no need to test more payloads for this engine
                            break

                        # Check for error-based indicators
                        elif detect_ssti_error(response_text):
                            findings.append({
                                'type': f'SSTI - {engine_name.upper()} (Error-Based)',
                                'severity': 'high',
                                'confidence': 'medium',
                                'url': url,
                                'method': 'GET',
                                'vulnerable_parameter': param_name,
                                'evidence': f'Template engine error detected! Server returned template-related error when processing payload "{payload}". This indicates template processing of user input. Error excerpt: {response_text[:400]}',
                                'payload': payload,
                                'template_engine': engine_name,
                                'test_description': description,
                                'response_status': response.status,
                                'response_length': len(response_text),
                                'cvss_score': 8.6,
                                'cwe': 'CWE-1336',
                                'impact': 'Server processes user input as template code, which could potentially be exploited for code execution. Error messages confirm template engine usage.',
                                'recommendation': '1. Sanitize user input before template rendering\n2. Use static templates instead of dynamic generation\n3. Enable template sandboxing\n4. Implement proper error handling',
                                'repro_command': f'curl "{test_url}"',
                                'test_url': test_url,
                            })
                            break

                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        continue

        # Test polyglot payloads (work across multiple engines)
        for polyglot_info in POLYGLOT_PAYLOADS:
            payload = polyglot_info['payload']
            expected_patterns = polyglot_info['expected_patterns']
            description = polyglot_info['description']

            for param_name, param_values in list(query_params.items()):
                test_params = query_params.copy()
                test_params[param_name] = [payload]

                test_query = urlencode(test_params, doseq=True)
                test_parsed = parsed._replace(query=test_query)
                test_url = urlunparse(test_parsed)

                try:
                    response = await session.get(test_url, allow_redirects=False, timeout=8)
                    response_text = await response.text()

                    # Check if any expected pattern matches
                    for expected in expected_patterns:
                        if detect_ssti_in_response(response_text, expected):
                            # Skip if expected value pre-exists in baseline
                            if detect_ssti_in_response(baseline_text, expected):
                                continue

                            ctx_snippet = extract_context(response_text, expected)

                            findings.append({
                                'type': 'SSTI - Polyglot Detection',
                                'severity': 'critical',
                                'confidence': 'high',
                                'url': url,
                                'method': 'GET',
                                'vulnerable_parameter': param_name,
                                'evidence': f'Server-Side Template Injection detected with polyglot payload! Payload "{payload}" ({description}) was evaluated. Expected pattern "{expected}" found in response. Context: ...{ctx_snippet}...',
                                'payload': payload,
                                'expected_result': expected,
                                'test_description': description,
                                'response_status': response.status,
                                'response_length': len(response_text),
                                'cvss_score': 9.6,
                                'cwe': 'CWE-1336',
                                'impact': 'Critical SSTI vulnerability detected! Server evaluates template expressions from user input, allowing arbitrary code execution. This can lead to complete system compromise.',
                                'recommendation': '1. Never use user input in template rendering\n2. Implement strict input validation\n3. Use template sandboxing\n4. Disable dangerous template features\n5. Apply principle of least privilege',
                                'repro_command': f'curl "{test_url}"',
                                'test_url': test_url,
                            })
                            break

                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue

        # Also test POST requests if it's a form endpoint
        if baseline_status == 200 and '<form' in baseline_text.lower():
            # Extract form fields
            form_fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', baseline_text, re.IGNORECASE)

            for field_name in form_fields[:3]:  # Test first 3 form fields
                # Test simple math expression
                test_payload = '{{7*7}}'

                try:
                    form_data = {field_name: test_payload}
                    response = await session.post(url, data=form_data, allow_redirects=False, timeout=8)
                    response_text = await response.text()

                    if '49' in response_text and test_payload not in response_text:
                        # Skip if '49' already appears in the baseline page
                        if '49' in baseline_text:
                            continue
                        ctx_snippet = extract_context(response_text, '49')

                        findings.append({
                            'type': 'SSTI - POST Form',
                            'severity': 'critical',
                            'confidence': 'high',
                            'url': url,
                            'method': 'POST',
                            'vulnerable_parameter': field_name,
                            'evidence': f'Server-Side Template Injection in POST form field "{field_name}"! Payload "{{{{7*7}}}}" was evaluated to "49". Context: ...{ctx_snippet}...',
                            'payload': test_payload,
                            'expected_result': '49',
                            'response_status': response.status,
                            'response_length': len(response_text),
                            'cvss_score': 9.8,
                            'cwe': 'CWE-1336',
                            'impact': 'Critical SSTI in POST form. Attacker can achieve Remote Code Execution through template injection in form submission.',
                            'recommendation': 'Sanitize all form input before template rendering. Never use user input directly in template engines.',
                            'repro_command': f'curl -X POST "{url}" -d "{field_name}={{{{7*7}}}}"',
                        })

                except Exception:
                    continue

    except Exception:
        pass

    return findings

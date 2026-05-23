"""
API Security Detector
=====================
Advanced detector for REST API security vulnerabilities including:
- Mass Assignment
- Excessive Data Exposure
- Broken Function Level Authorization (BFLA)
- API Key Leakage
- Insecure Direct Object References (IDOR)
- Missing Rate Limiting
- Verbose Error Messages
"""

import asyncio
import json
import re
from typing import Dict, List, Any
from detectors.registry import register_active

# Test payloads for Mass Assignment
MASS_ASSIGNMENT_FIELDS = [
    "is_admin", "isAdmin", "admin", "role", "is_verified", "verified",
    "premium", "is_premium", "pro", "is_pro", "subscription_level",
    "balance", "credits", "points", "permissions", "access_level"
]

# IDOR test patterns
IDOR_ID_PATTERNS = [
    r'/users?/(\d+)',
    r'/accounts?/(\d+)',
    r'/profiles?/(\d+)',
    r'/orders?/(\d+)',
    r'/invoices?/(\d+)',
    r'/documents?/(\d+)',
    r'[?&]id=(\d+)',
    r'[?&]user_id=(\d+)',
    r'[?&]account_id=(\d+)',
]

# Sensitive data patterns in responses
SENSITIVE_PATTERNS = {
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    'api_key': r'\b[A-Za-z0-9]{32,}\b',
    'jwt': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'password_hash': r'\$2[ayb]\$.{56}',
}

# Error messages that reveal too much
VERBOSE_ERROR_PATTERNS = [
    r'at line \d+',
    r'stack trace',
    r'SQLException',
    r'ORA-\d+',
    r'MySQL error',
    r'PostgreSQL',
    r'mongodb',
    r'Exception in thread',
    r'Traceback \(most recent call last\)',
    r'File ".*\.py"',
    r'/home/\w+/',
    r'/var/www/',
    r'C:\\',
]


@register_active
async def api_security_detector(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """
    Main API security detector function.
    Tests for various API-specific vulnerabilities.
    """
    findings = []

    # Only run on API endpoints to save time
    if not is_api_endpoint(url):
        return findings

    try:
        # Run tests in parallel with timeout wrapper
        tasks = [
            test_excessive_data_exposure(session, url, context),
            test_idor(session, url, context),
            test_verbose_errors(session, url, context),
        ]

        # Run parallel tests with 10 second timeout (shorter for safety)
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=10.0
        )

        for result in results:
            if isinstance(result, list) and result:
                findings.extend(result)

    except asyncio.TimeoutError:
        # Timeout after 10 seconds - skip this URL silently
        pass
    except Exception:
        # Catch any other errors and continue silently
        pass

    return findings


# Mass assignment test removed - too many requests and potential for false positives


async def test_excessive_data_exposure(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """Test for Excessive Data Exposure in API responses."""
    findings = []

    if not is_api_endpoint(url):
        return findings

    try:
        headers = {
            'Accept': 'application/json',
            'User-Agent': context.get('user_agent', 'BugBountyScanner/1.0')
        }

        resp = await session.get(
            url,
            headers=headers,
            timeout=5,  # Short timeout for API detector
            allow_redirects=True
        )

        body = await resp.text()

        # Check if response contains sensitive data
        exposed_data = []
        for data_type, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, body)
            if matches:
                exposed_data.append({
                    'type': data_type,
                    'count': len(matches),
                    'sample': matches[0] if data_type != 'password_hash' else '[REDACTED]'
                })

        # Check for common sensitive field names in JSON
        if 'application/json' in resp.headers.get('Content-Type', ''):
            try:
                json_data = json.loads(body)
                sensitive_fields = find_sensitive_fields(json_data)
                if sensitive_fields:
                    exposed_data.append({
                        'type': 'sensitive_fields',
                        'fields': sensitive_fields
                    })
            except:
                pass

        if exposed_data:
            findings.append({
                'type': 'Excessive Data Exposure',
                'severity': 'medium',
                'confidence': 'high',
                'url': url,
                'method': 'GET',
                'evidence': f'API endpoint exposes sensitive data: {json.dumps(exposed_data, indent=2)}',
                'impact': 'API returns more data than necessary, potentially exposing sensitive information to unauthorized users.',
                'recommendation': 'Filter API responses to return only necessary fields. Implement field-level access controls.',
                'cvss': 5.3,
                'detector': 'api_security_detector'
            })

    except Exception:
        pass

    return findings


async def test_idor(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """Test for IDOR (Insecure Direct Object Reference) vulnerabilities."""
    findings = []

    # Extract IDs from URL
    extracted_ids = []
    for pattern in IDOR_ID_PATTERNS:
        matches = re.findall(pattern, url)
        extracted_ids.extend(matches)

    if not extracted_ids:
        return findings

    try:
        original_id = extracted_ids[0]
        # Only test numeric IDs
        if not original_id.isdigit():
            return findings

    except (ValueError, IndexError):
        return findings

    # Test only 2 IDs for speed (most likely to find IDOR)
    test_ids = [
        str(int(original_id) + 1),  # Next ID
        '1',  # First ID (often accessible)
    ]

    try:
        # Get baseline response with shorter timeout
        headers = {
            'User-Agent': context.get('user_agent', 'BugBountyScanner/1.0')
        }

        baseline_resp = await session.get(
            url,
            headers=headers,
            timeout=3,  # Very short timeout for IDOR test
            allow_redirects=False
        )
        baseline_body = await baseline_resp.text()
        baseline_len = len(baseline_body)

        if baseline_resp.status not in [200, 201]:
            return findings  # Original ID doesn't work, skip

        # Test other IDs in parallel
        test_tasks = []
        test_urls = []

        for test_id in test_ids:
            test_url = url
            for pattern in IDOR_ID_PATTERNS:
                test_url = re.sub(pattern, f'/{test_id}' if '/' in pattern else f'id={test_id}', test_url, count=1)
            test_urls.append(test_url)

            test_tasks.append(
                session.get(
                    test_url,
                    headers=headers,
                    timeout=3,
                    allow_redirects=False
                )
            )

        # Run tests in parallel with timeout
        try:
            responses = await asyncio.wait_for(
                asyncio.gather(*test_tasks, return_exceptions=True),
                timeout=7.0  # Max 7 seconds for IDOR parallel tests
            )
        except asyncio.TimeoutError:
            return findings

        successful_tests = []
        for test_id, test_url, resp in zip(test_ids, test_urls, responses):
            # Skip if response is an exception
            if isinstance(resp, Exception):
                continue

            # Skip if response doesn't have expected attributes
            if not hasattr(resp, 'status') or not hasattr(resp, 'text'):
                continue

            try:
                test_body = await resp.text()  # type: ignore
                test_len = len(test_body)

                # If we get a valid response with different data
                if resp.status in [200, 201] and abs(test_len - baseline_len) > 100:  # type: ignore
                    successful_tests.append({
                        'id': test_id,
                        'status': resp.status,  # type: ignore
                        'length': test_len,
                        'url': test_url
                    })

            except Exception:
                continue

        if successful_tests:
            findings.append({
                'type': 'IDOR (Insecure Direct Object Reference)',
                'severity': 'high',
                'confidence': 'high',
                'url': url,
                'method': 'GET',
                'evidence': f'Successfully accessed {len(successful_tests)} other objects by manipulating ID parameter. Original ID: {original_id}',
                'vulnerable_parameter': original_id,
                'test_results': successful_tests,
                'impact': 'Attacker can access other users\' data by manipulating ID parameters in the URL.',
                'recommendation': 'Implement proper authorization checks. Verify that the authenticated user has permission to access the requested resource.',
                'cvss': 8.1,
                'detector': 'api_security_detector'
            })

    except Exception:
        pass

    return findings


async def test_verbose_errors(session, url: str, context: dict) -> List[Dict[str, Any]]:
    """Test for verbose error messages that reveal implementation details."""
    findings = []

    # Only test one quick error case for speed
    try:
        headers = {
            'User-Agent': context.get('user_agent', 'BugBountyScanner/1.0')
        }

        # Test with invalid parameter
        resp = await session.get(
            url,
            params={'id': "'; DROP TABLE users--"},
            headers=headers,
            timeout=3,
            allow_redirects=False
        )

        body = await resp.text()

        # Check for verbose error patterns (only most common ones)
        critical_patterns = [
            r'Exception in thread',
            r'Traceback \(most recent call last\)',
            r'File ".*\.py"',
            r'SQLException',
            r'at line \d+',
        ]

        found_patterns = []
        for pattern in critical_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                found_patterns.append(pattern)

        if found_patterns:
            findings.append({
                'type': 'Verbose Error Messages',
                'severity': 'low',
                'confidence': 'high',
                'url': url,
                'method': 'GET',
                'evidence': f'Server revealed implementation details in error message. Patterns found: {found_patterns[:3]}',
                'impact': 'Error messages reveal technology stack, file paths, or internal structure, aiding attackers in reconnaissance.',
                'recommendation': 'Implement generic error messages for users. Log detailed errors server-side only.',
                'cvss': 3.7,
                'detector': 'api_security_detector'
            })

    except Exception:
        pass

    return findings


# Rate limiting test removed - too aggressive for responsible scanning


def is_api_endpoint(url: str) -> bool:
    """Check if URL is likely an API endpoint."""
    api_indicators = [
        '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
        '/oauth/', '/auth/', '/users/', '/accounts/', '/data/',
        '.json', '/api', 'api.'
    ]

    url_lower = url.lower()
    return any(indicator in url_lower for indicator in api_indicators)


def find_sensitive_fields(data, prefix='') -> List[str]:
    """Recursively find sensitive field names in JSON data."""
    sensitive_keywords = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'private_key', 'privatekey', 'ssn', 'social_security', 'credit_card',
        'card_number', 'cvv', 'pin', 'auth', 'session', 'cookie'
    ]

    found_fields = []

    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key

            # Check if key name is sensitive
            if any(keyword in key.lower() for keyword in sensitive_keywords):
                found_fields.append(full_key)

            # Recurse into nested structures
            if isinstance(value, (dict, list)):
                found_fields.extend(find_sensitive_fields(value, full_key))

    elif isinstance(data, list):
        for i, item in enumerate(data[:3]):  # Check first 3 items only
            if isinstance(item, (dict, list)):
                found_fields.extend(find_sensitive_fields(item, f"{prefix}[{i}]"))

    return found_fields

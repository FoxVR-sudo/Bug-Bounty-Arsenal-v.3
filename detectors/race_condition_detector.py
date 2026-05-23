"""
Race Condition Vulnerability Detector
Detects race condition vulnerabilities through concurrent request testing
Reward potential: $500-5000+

Detection techniques:
- Concurrent requests to critical endpoints
- Payment endpoint testing (double spending)
- Account creation rate limit bypass
- Voucher/coupon redemption multiple times
- Transaction ID monitoring
- Balance/quantity inconsistency detection

CWE: CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
OWASP: A04:2021 - Insecure Design
"""

import asyncio
import re
import time
import hashlib
from collections import Counter
from .registry import register_active

# Keywords that indicate critical endpoints prone to race conditions
CRITICAL_ENDPOINT_KEYWORDS = [
    'payment', 'pay', 'checkout', 'purchase', 'buy',
    'voucher', 'coupon', 'redeem', 'claim', 'promo',
    'transfer', 'withdraw', 'deposit', 'balance',
    'create', 'register', 'signup', 'account',
    'vote', 'like', 'follow', 'subscribe',
    'cart', 'order', 'transaction',
    'credit', 'debit', 'reward', 'gift',
]

# Response patterns indicating success/failure
SUCCESS_INDICATORS = [
    r'"success"\s*:\s*true',
    r'"status"\s*:\s*"success"',
    r'"error"\s*:\s*false',
    r'"approved"\s*:\s*true',
    r'transaction.*completed',
    r'payment.*successful',
    r'successfully.*created',
    r'redeemed successfully',
    r'"message"\s*:\s*"(?:success|approved|completed)"',
]

ERROR_INDICATORS = [
    r'"success"\s*:\s*false',
    r'"status"\s*:\s*"(?:error|failed)"',
    r'"error"\s*:\s*true',
    r'insufficient.*(?:balance|funds)',
    r'already.*(?:redeemed|used|claimed)',
    r'rate.*limit.*exceeded',
    r'too.*many.*requests',
    r'duplicate.*transaction',
    r'already.*exists',
]

# Transaction/order ID patterns
TRANSACTION_ID_PATTERNS = [
    r'(?:transaction|order|payment)_?(?:id|num|ref)[\'":\s]+([a-zA-Z0-9_-]{8,})',
    r'(?:txn|tx|ord)[\'":\s]+([a-zA-Z0-9_-]{8,})',
    r'"id"[\s:]+(\d{6,})',
]


def is_critical_endpoint(url):
    """Check if URL contains keywords indicating critical endpoint"""
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in CRITICAL_ENDPOINT_KEYWORDS)


def extract_transaction_ids(response_text):
    """Extract transaction/order IDs from response"""
    transaction_ids = []
    for pattern in TRANSACTION_ID_PATTERNS:
        matches = re.findall(pattern, response_text, re.IGNORECASE)
        transaction_ids.extend(matches)
    return transaction_ids


def analyze_response_consistency(responses):
    """
    Analyze responses for inconsistencies that indicate race condition

    Returns:
    - duplicate_ids: List of duplicate transaction IDs (should be unique)
    - status_inconsistency: Mixed success/error statuses
    - content_variance: High variance in response content
    """
    all_transaction_ids = []
    success_count = 0
    error_count = 0
    response_hashes = []

    for resp_text, status in responses:
        # Extract transaction IDs
        txn_ids = extract_transaction_ids(resp_text)
        all_transaction_ids.extend(txn_ids)

        # Check success/error indicators
        has_success = any(re.search(pattern, resp_text, re.IGNORECASE) for pattern in SUCCESS_INDICATORS)
        has_error = any(re.search(pattern, resp_text, re.IGNORECASE) for pattern in ERROR_INDICATORS)

        if has_success:
            success_count += 1
        if has_error:
            error_count += 1

        # Hash response content for variance analysis
        content_hash = hashlib.md5(resp_text.encode()).hexdigest()
        response_hashes.append(content_hash)

    # Find duplicate transaction IDs (should be unique if no race condition)
    duplicate_ids = [tid for tid, count in Counter(all_transaction_ids).items() if count > 1]

    # Status inconsistency: some succeed, some fail
    status_inconsistency = (success_count > 0 and error_count > 0)

    # Content variance: different responses (might indicate successful race)
    unique_responses = len(set(response_hashes))
    content_variance = unique_responses / len(responses) if responses else 0

    return {
        'duplicate_ids': duplicate_ids,
        'success_count': success_count,
        'error_count': error_count,
        'status_inconsistency': status_inconsistency,
        'unique_responses': unique_responses,
        'total_responses': len(responses),
        'content_variance': content_variance,
    }


async def send_concurrent_requests(url, session, method='GET', data=None, count=50):
    """
    Send multiple concurrent requests to the same endpoint

    Returns list of (response_text, status_code) tuples
    """
    async def single_request():
        try:
            if method.upper() == 'POST':
                response = await session.post(url, data=data, allow_redirects=False, timeout=10)
            else:
                response = await session.get(url, allow_redirects=False, timeout=10)

            text = await response.text()
            return (text, response.status)
        except Exception as e:
            return (str(e), 0)

    # Send all requests concurrently
    tasks = [single_request() for _ in range(count)]
    responses = await asyncio.gather(*tasks)

    return responses


@register_active
async def race_condition_detector(session, url, context):
    """
    Detect race condition vulnerabilities.

    ⚠️  REQUIRES allow_destructive=True in context.
    Sends multiple concurrent requests which can stress-test the server.
    Use only against targets you are authorised to test.

    Returns list of race condition vulnerability findings.
    """
    findings = []

    # Gate: concurrent burst requests can look like a DoS — require explicit opt-in
    if not bool((context or {}).get('allow_destructive', False)):
        import logging
        logging.getLogger(__name__).debug(
            'race_condition_detector: skipped (requires allow_destructive=True)'
        )
        return findings

    try:
        # Only test endpoints that are likely to have race conditions
        if not is_critical_endpoint(url):
            return findings

        # Get baseline response
        baseline_response = await session.get(url, allow_redirects=False)
        baseline_text = await baseline_response.text()
        baseline_status = baseline_response.status

        # Skip if baseline request fails
        if baseline_status >= 400:
            return findings

        # Test 1: Concurrent GET requests (capped at 10 to avoid DoS)
        import logging as _log
        _log.getLogger(__name__).info("race_condition_detector: testing %s with 10 concurrent GET requests", url)

        start_time = time.time()
        responses = await send_concurrent_requests(url, session, method='GET', count=10)
        elapsed = time.time() - start_time

        # Analyze responses
        analysis = analyze_response_consistency(responses)

        # Check for duplicate transaction IDs (major indicator)
        if analysis['duplicate_ids']:
            findings.append({
                'type': 'Race Condition - Duplicate Transaction IDs',
                'severity': 'critical',
                'confidence': 'high',
                'url': url,
                'method': 'GET',
                'evidence': f'Race condition detected! {len(analysis["duplicate_ids"])} duplicate transaction IDs found across {analysis["total_responses"]} concurrent requests. Duplicate IDs: {", ".join(analysis["duplicate_ids"][:5])}. This indicates improper synchronization allowing multiple operations to use the same identifier.',
                'concurrent_requests': 10,
                'duplicate_transaction_ids': analysis['duplicate_ids'],
                'success_count': analysis['success_count'],
                'error_count': analysis['error_count'],
                'elapsed_time': f'{elapsed:.2f}s',
                'cvss_score': 9.1,
                'cwe': 'CWE-362',
                'impact': 'Critical race condition vulnerability! Attacker can exploit this to perform double-spending attacks, redeem vouchers multiple times, bypass rate limits, or cause data inconsistency. Multiple operations can share the same transaction ID, leading to financial loss or unauthorized access.',
                'recommendation': '1. Implement proper locking mechanisms (mutex, semaphore)\n2. Use database transactions with proper isolation levels\n3. Generate unique transaction IDs atomically\n4. Implement idempotency keys for critical operations\n5. Use distributed locks for multi-server deployments\n6. Add rate limiting per user/session\n7. Implement FIFO queuing for critical operations',
                'repro_command': f'# Run 10 concurrent requests:\nfor i in {{1..10}}; do curl "{url}" & done; wait',
            })

        # Check for status inconsistency (some succeed, some fail)
        elif analysis['status_inconsistency'] and analysis['success_count'] > 1:
            findings.append({
                'type': 'Race Condition - Inconsistent State',
                'severity': 'high',
                'confidence': 'medium',
                'url': url,
                'method': 'GET',
                'evidence': f'Race condition suspected! Inconsistent responses detected: {analysis["success_count"]} successes and {analysis["error_count"]} errors out of {analysis["total_responses"]} concurrent requests. This suggests improper state synchronization where some requests succeed while others fail due to race conditions.',
                'concurrent_requests': 10,
                'success_count': analysis['success_count'],
                'error_count': analysis['error_count'],
                'unique_responses': analysis['unique_responses'],
                'elapsed_time': f'{elapsed:.2f}s',
                'cvss_score': 7.8,
                'cwe': 'CWE-362',
                'impact': 'Race condition may allow attackers to bypass rate limits, perform multiple operations that should be restricted to once, or exploit timing windows in critical business logic.',
                'recommendation': '1. Implement atomic operations\n2. Use database transactions properly\n3. Add pessimistic locking for critical sections\n4. Test concurrent access patterns\n5. Implement proper error handling for concurrent modifications',
                'repro_command': f'# Run 10 concurrent requests:\nfor i in {{1..10}}; do curl "{url}" & done; wait',
            })

        # Check for high content variance (different responses)
        elif analysis['content_variance'] > 0.3 and analysis['unique_responses'] > 5:
            findings.append({
                'type': 'Race Condition - High Response Variance',
                'severity': 'medium',
                'confidence': 'low',
                'url': url,
                'method': 'GET',
                'evidence': f'Possible race condition detected through response variance. {analysis["unique_responses"]} unique responses out of {analysis["total_responses"]} concurrent requests (variance: {analysis["content_variance"]:.1%}). High variance may indicate race conditions in data generation or retrieval.',
                'concurrent_requests': 10,
                'unique_responses': analysis['unique_responses'],
                'total_responses': analysis['total_responses'],
                'content_variance': f'{analysis["content_variance"]:.1%}',
                'elapsed_time': f'{elapsed:.2f}s',
                'cvss_score': 6.5,
                'cwe': 'CWE-362',
                'impact': 'Potential race condition in data processing or generation. May lead to inconsistent data, information disclosure, or business logic bypasses.',
                'recommendation': '1. Review concurrent data access patterns\n2. Implement proper synchronization\n3. Use atomic counters and generators\n4. Add caching with proper invalidation',
                'repro_command': f'# Run 10 concurrent requests and compare responses:\nfor i in {{1..10}}; do curl "{url}" > "response_$i.txt" & done; wait',
            })

        # Test 2: For POST endpoints with forms
        if '<form' in baseline_text.lower():
            # Extract form fields
            form_fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', baseline_text, re.IGNORECASE)

            if form_fields:
                # Create test data
                test_data = {field: 'test_value' for field in form_fields[:5]}

                _log.getLogger(__name__).info("race_condition_detector: testing POST form with 8 concurrent requests")

                post_responses = await send_concurrent_requests(
                    url, session, method='POST', data=test_data, count=8
                )

                post_analysis = analyze_response_consistency(post_responses)

                # Check for duplicate IDs in POST responses
                if post_analysis['duplicate_ids']:
                    findings.append({
                        'type': 'Race Condition - POST Form Duplicate IDs',
                        'severity': 'critical',
                        'confidence': 'high',
                        'url': url,
                        'method': 'POST',
                        'evidence': f'Race condition in POST form! {len(post_analysis["duplicate_ids"])} duplicate transaction/order IDs found. Duplicate IDs: {", ".join(post_analysis["duplicate_ids"][:5])}. This can lead to payment processing issues, order duplication, or data corruption.',
                        'form_fields': list(test_data.keys()),
                        'concurrent_requests': 8,
                        'duplicate_ids': post_analysis['duplicate_ids'],
                        'success_count': post_analysis['success_count'],
                        'cvss_score': 9.3,
                        'cwe': 'CWE-362',
                        'impact': 'Critical race condition in form submission! Attacker can submit multiple forms concurrently to exploit double-spending, duplicate orders, or bypass one-time restrictions.',
                        'recommendation': '1. Implement CSRF tokens with one-time use\n2. Use idempotency keys for all POST operations\n3. Add form submission locks\n4. Generate unique IDs atomically\n5. Implement database constraints (unique keys)',
                        'repro_command': f'# Test with concurrent POST:\nfor i in {{1..8}}; do curl -X POST "{url}" -d "field=test" & done; wait',
                    })

                elif post_analysis['success_count'] > 3:
                    # Multiple successful submissions might indicate rate limit bypass
                    findings.append({
                        'type': 'Race Condition - Rate Limit Bypass',
                        'severity': 'high',
                        'confidence': 'medium',
                        'url': url,
                        'method': 'POST',
                        'evidence': f'Possible race condition allowing rate limit bypass. {post_analysis["success_count"]} out of 8 concurrent POST requests succeeded. This may allow bypassing restrictions on account creation, voucher redemption, or other limited operations.',
                        'concurrent_requests': 8,
                        'success_count': post_analysis['success_count'],
                        'error_count': post_analysis['error_count'],
                        'cvss_score': 7.5,
                        'cwe': 'CWE-362',
                        'impact': 'Race condition may allow bypassing rate limits, creating multiple accounts, or performing restricted operations multiple times.',
                        'recommendation': '1. Implement distributed rate limiting\n2. Use atomic counters\n3. Add queue-based processing\n4. Implement user-based locks',
                        'repro_command': f'# Test rate limit with concurrent requests:\nfor i in {{1..8}}; do curl -X POST "{url}" -d "field=test" & done; wait',
                    })

    except Exception:
        pass

    return findings

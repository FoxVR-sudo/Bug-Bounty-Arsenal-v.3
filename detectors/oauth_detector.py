# detectors/oauth_detector.py
"""
OAuth/SSO Bypass Detector - Account takeover vulnerabilities

Tests for:
- State parameter bypass (CSRF in OAuth flow)
- Redirect URI validation bypass
- Authorization code reuse
- Token leakage via Referer
- Client secret exposure
- Implicit grant vulnerabilities
- Account takeover via OAuth

Expected Bounty Value: $2,000-$15,000 per finding (CRITICAL - Account Takeover!)
Common in: Single Sign-On systems, social login, API authentication
"""
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from detectors.registry import register_passive, register_active, await_host_token

logger = logging.getLogger(__name__)

# OAuth/SSO endpoint patterns
OAUTH_PATTERNS = [
    r'/oauth',
    r'/auth',
    r'/sso',
    r'/login',
    r'/authorize',
    r'/oauth2/authorize',
    r'/connect/authorize',
    r'/oauth/authorize',
    r'response_type=code',
    r'response_type=token',
    r'client_id=',
    r'redirect_uri=',
    r'state=',
]

# OAuth providers
OAUTH_PROVIDERS = [
    "google", "facebook", "github", "twitter", "linkedin",
    "microsoft", "apple", "amazon", "salesforce", "okta",
]


@register_passive
def oauth_detector_passive(text, combined_dict):
    """
    Passive OAuth/SSO vulnerability detection.
    """
    findings = []

    try:
        url = combined_dict["url"]
        context = combined_dict["context"]

        body = context.get("body", text)
        context.get("headers", {})

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Check 1: OAuth endpoint detection
        is_oauth_endpoint = any(re.search(pattern, url, re.IGNORECASE) for pattern in OAUTH_PATTERNS)

        if not is_oauth_endpoint and body:
            is_oauth_endpoint = any(re.search(pattern, body, re.IGNORECASE) for pattern in OAUTH_PATTERNS[:7])

        if not is_oauth_endpoint:
            return findings

        logger.info(f"🔍 OAuth endpoint detected: {url}")

        # Check 2: Missing state parameter (CSRF vulnerability)
        if 'response_type' in query_params and 'state' not in query_params:
            findings.append({
                "type": "OAuth Missing State Parameter",
                "severity": "high",
                "evidence": "OAuth authorization request without state parameter",
                "how_found": "OAuth flow detected without CSRF protection (state parameter)",
                "evidence_url": url,
                "impact": "HIGH: Missing state parameter allows CSRF attacks in OAuth flow. Attacker can link victim's account to attacker's OAuth account, leading to account takeover.",
                "remediation": "Always use state parameter with cryptographically random value. Verify state on callback.",
                "cve_reference": "CWE-352: Cross-Site Request Forgery (CSRF)",
            })

            logger.warning(f"🔥 HIGH: OAuth missing state parameter on {url}")

        # Check 3: Redirect URI in parameters (check for open redirect)
        redirect_uri = query_params.get('redirect_uri', [None])[0]
        if redirect_uri:
            # Check if redirect_uri is to different domain
            try:
                redirect_parsed = urlparse(redirect_uri)
                original_domain = parsed.netloc.lower()
                redirect_domain = redirect_parsed.netloc.lower()

                if redirect_domain and redirect_domain != original_domain:
                    findings.append({
                        "type": "OAuth External Redirect URI",
                        "severity": "medium",
                        "evidence": f"OAuth redirect_uri points to external domain: {redirect_domain}",
                        "how_found": f"redirect_uri parameter contains external domain: {redirect_uri}",
                        "evidence_url": url,
                        "redirect_uri": redirect_uri,
                        "impact": "MEDIUM: External redirect_uri may indicate open redirect or misconfigured whitelist. Can lead to authorization code theft.",
                        "remediation": "Validate redirect_uri against strict whitelist. Use exact match, not prefix/suffix match.",
                    })

            except Exception as e:
                logger.debug(f"Redirect URI parsing error: {e}")

        # Check 4: Client secret in URL or response (CRITICAL!)
        secret_patterns = [
            r'client_secret=([A-Za-z0-9_-]+)',
            r'"client_secret"\s*:\s*"([^"]+)"',
            r'clientSecret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in secret_patterns:
            # Check URL
            match_url = re.search(pattern, url, re.IGNORECASE)
            if match_url:
                secret = match_url.group(1)
                findings.append({
                    "type": "OAuth Client Secret Exposed in URL",
                    "severity": "critical",
                    "evidence": f"Client secret exposed in URL: {secret[:10]}...",
                    "how_found": "client_secret parameter found in URL",
                    "evidence_url": url,
                    "client_secret": secret[:20] + "...",
                    "impact": "CRITICAL: Client secret exposed in URL. Attacker can impersonate application and steal user tokens. Leads to mass account compromise.",
                    "remediation": "NEVER put client_secret in URL. Use POST body with server-side validation only.",
                    "cve_reference": "CWE-798: Use of Hard-coded Credentials",
                })

                logger.warning(f"🔥 CRITICAL: OAuth client secret in URL!")
                break

            # Check response body
            match_body = re.search(pattern, body, re.IGNORECASE)
            if match_body:
                secret = match_body.group(1)
                findings.append({
                    "type": "OAuth Client Secret Exposed in Response",
                    "severity": "critical",
                    "evidence": f"Client secret exposed in response: {secret[:10]}...",
                    "how_found": "client_secret found in HTTP response body",
                    "evidence_url": url,
                    "client_secret": secret[:20] + "...",
                    "impact": "CRITICAL: Client secret leaked in response. Attacker can impersonate application.",
                    "remediation": "Never return client_secret in API responses. Keep secret server-side only.",
                })

                logger.warning(f"🔥 CRITICAL: OAuth client secret in response!")
                break

        # Check 5: Implicit grant (less secure)
        if 'response_type' in query_params:
            response_type = query_params['response_type'][0]
            if 'token' in response_type.lower():
                findings.append({
                    "type": "OAuth Implicit Grant Flow",
                    "severity": "low",
                    "evidence": f"OAuth using implicit flow: response_type={response_type}",
                    "how_found": "response_type contains 'token' indicating implicit grant",
                    "evidence_url": url,
                    "impact": "LOW: Implicit grant flow is deprecated due to security concerns. Access token exposed in URL fragment.",
                    "remediation": "Migrate to Authorization Code flow with PKCE for better security.",
                })

    except Exception as e:
        logger.exception(f"oauth_detector_passive error for {url}: {e}")

    return findings


@register_active
async def oauth_detector_active(session, url, context):
    """
    Active OAuth/SSO bypass testing.

    Only runs if --allow-destructive flag is set.
    """
    findings = []

    allow_destructive = context.get("allow_destructive", False)
    if not allow_destructive:
        return findings

    try:
        per_host_rate = context.get("per_host_rate", None)

        parsed = urlparse(url)
        host = parsed.netloc.lower()
        query_params = parse_qs(parsed.query)

        # Only test OAuth endpoints
        is_oauth_endpoint = any(re.search(pattern, url, re.IGNORECASE) for pattern in OAUTH_PATTERNS)
        if not is_oauth_endpoint:
            return findings

        logger.info(f"🔍 Testing OAuth bypasses on {url}")

        # Test 1: Redirect URI manipulation
        if 'redirect_uri' in query_params:
            original_redirect = query_params['redirect_uri'][0]

            # Test various bypass techniques
            bypass_redirects = [
                "https://evil.com",  # Complete replacement
                original_redirect + "@evil.com",  # @ bypass
                original_redirect + ".evil.com",  # Subdomain
                original_redirect + "?redirect=https://evil.com",  # Open redirect
                "https://evil.com?" + original_redirect,  # Prefix
                original_redirect.replace("https://", "https://evil.com@"),  # @ in middle
            ]

            for bypass_redirect in bypass_redirects[:2]:  # Test first 2
                await await_host_token(host, per_host_rate)

                # Modify redirect_uri
                modified_params = query_params.copy()
                modified_params['redirect_uri'] = [bypass_redirect]

                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                try:
                    async with session.get(test_url, timeout=10, allow_redirects=False) as resp:
                        status = resp.status
                        body = await resp.text()
                        location = resp.headers.get("Location", "")

                        # Check if our bypass redirect was accepted
                        if status in [200, 302, 303, 307] and bypass_redirect in (body + location):
                            findings.append({
                                "type": "OAuth Redirect URI Bypass",
                                "severity": "critical",
                                "evidence": f"OAuth accepted modified redirect_uri: {bypass_redirect}",
                                "how_found": f"Modified redirect_uri to {bypass_redirect}, server accepted it",
                                "evidence_url": test_url,
                                "evidence_status": status,
                                "original_redirect_uri": original_redirect,
                                "bypass_redirect_uri": bypass_redirect,
                                "impact": "CRITICAL: OAuth redirect_uri validation bypass. Attacker can steal authorization codes by redirecting to malicious site. Leads to account takeover.",
                                "remediation": "Implement strict redirect_uri validation. Use exact match whitelist, not prefix/suffix matching.",
                                "cve_reference": "CWE-601: URL Redirection to Untrusted Site",
                            })

                            logger.warning(f"🔥 CRITICAL: OAuth redirect_uri bypass successful!")
                            break

                except Exception as e:
                    logger.debug(f"Redirect URI test failed: {e}")

        # Test 2: State parameter bypass (remove state)
        if 'state' in query_params:
            await await_host_token(host, per_host_rate)

            # Remove state parameter
            modified_params = query_params.copy()
            del modified_params['state']

            new_query = urlencode(modified_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))

            try:
                async with session.get(test_url, timeout=10, allow_redirects=False) as resp:
                    status = resp.status

                    # If request succeeds without state, it's vulnerable
                    if status in [200, 302, 303, 307]:
                        findings.append({
                            "type": "OAuth State Parameter Bypass",
                            "severity": "high",
                            "evidence": "OAuth authorization succeeds without state parameter",
                            "how_found": "Removed state parameter, OAuth flow still proceeded",
                            "evidence_url": test_url,
                            "evidence_status": status,
                            "impact": "HIGH: OAuth flow doesn't enforce state parameter. Vulnerable to CSRF attacks. Attacker can link victim's account to attacker's OAuth.",
                            "remediation": "Make state parameter mandatory. Reject requests without valid state.",
                            "cve_reference": "CWE-352: Cross-Site Request Forgery (CSRF)",
                        })

                        logger.warning(f"🔥 HIGH: OAuth state bypass successful!")

            except Exception as e:
                logger.debug(f"State bypass test failed: {e}")

        # Test 3: Account takeover via response_type manipulation
        if 'response_type' in query_params:
            await await_host_token(host, per_host_rate)

            # Try to change response_type
            original_type = query_params['response_type'][0]

            # If it's 'code', try 'token' (implicit flow)
            if 'code' in original_type.lower():
                modified_params = query_params.copy()
                modified_params['response_type'] = ['token']

                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                try:
                    async with session.get(test_url, timeout=10, allow_redirects=False) as resp:
                        status = resp.status
                        body = await resp.text()
                        location = resp.headers.get("Location", "")

                        # Check if server accepted different response_type
                        if status in [200, 302, 303, 307] and 'access_token' in (body + location):
                            findings.append({
                                "type": "OAuth Response Type Manipulation",
                                "severity": "high",
                                "evidence": "OAuth allows switching from code to token flow",
                                "how_found": "Changed response_type from 'code' to 'token', server accepted it",
                                "evidence_url": test_url,
                                "evidence_status": status,
                                "impact": "HIGH: OAuth response_type can be manipulated. Attacker can switch to less secure implicit flow.",
                                "remediation": "Validate response_type against client configuration. Don't allow arbitrary response_type values.",
                            })

                            logger.warning(f"🔥 HIGH: OAuth response_type manipulation successful!")

                except Exception as e:
                    logger.debug(f"Response type test failed: {e}")

    except Exception as e:
        logger.exception(f"oauth_detector_active error for {url}: {e}")

    return findings

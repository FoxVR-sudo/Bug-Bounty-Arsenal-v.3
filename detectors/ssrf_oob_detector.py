# detectors/ssrf_oob_detector.py
"""Out-of-band SSRF detector using interact.sh for callback verification."""
import asyncio
import base64
import logging
import secrets
from urllib.parse import urlparse, parse_qs, urlencode

from detectors.registry import register_active, await_host_token
from detectors.interactsh_client import get_interactsh_client

logger = logging.getLogger(__name__)

# Grace period for callback propagation (seconds)
CALLBACK_WAIT_SECONDS = 2
CALLBACK_RETRIES = 3


@register_active
async def ssrf_oob_detector(session, url, context):
    """
    Out-of-Band SSRF detector using DNS callbacks.

    Only reports SSRF when:
    1. Parameter injection successful
    2. DNS callback received (proves external request made)

    This eliminates false positives from reflection-based detection.
    """
    findings = []

    if not url:
        return findings

    allow_destructive = context.get("allow_destructive", False)
    if not allow_destructive:
        logger.debug("ssrf_oob_detector: Skipping (requires --allow-destructive flag)")
        return findings

    per_host_rate = context.get("per_host_rate", None)

    try:
        interact_client = await get_interactsh_client()
        if not interact_client or not interact_client.base_domain:
            logger.debug("Interactsh client unavailable, skipping OOB SSRF detection")
            return findings

        parsed = urlparse(url)
        host = parsed.netloc.lower()
        existing_qs = parse_qs(parsed.query, keep_blank_values=True)

        # Find candidate parameters for SSRF
        candidate_params = list(existing_qs.keys()) or [
            "url", "uri", "target", "dest", "destination", "redirect",
            "path", "file", "page", "link", "src", "source"
        ]

        # Limit testing to avoid excessive requests
        for param in candidate_params[:5]:

            # Generate unique marker for this test
            marker = secrets.token_hex(6)
            callback_url = interact_client.generate_url(marker)

            # Build test URL
            new_qs = dict(existing_qs)
            new_qs[param] = [callback_url]
            test_query = urlencode(new_qs, doseq=True)
            test_url = parsed._replace(query=test_query).geturl()

            # Throttle
            await await_host_token(host, per_host_rate)

            try:
                # Make request with callback payload
                async with session.get(test_url, allow_redirects=True, timeout=10) as resp:
                    try:
                        body = await resp.text()
                    except Exception:
                        body = ""

                    status = resp.status
                    headers = dict(resp.headers)

                await asyncio.sleep(CALLBACK_WAIT_SECONDS)
                interaction = await interact_client.check_callback(
                    marker,
                    timeout=CALLBACK_WAIT_SECONDS,
                    max_retries=CALLBACK_RETRIES,
                )

                if interaction:
                    protocol = interaction.get("protocol") or interaction.get("protocol-type", "unknown")
                    full_id = interaction.get("full-id") or interaction.get("full_id")
                    raw_request = interaction.get("raw-request") or interaction.get("raw_request")
                    if raw_request:
                        try:
                            raw_request = base64.b64decode(raw_request).decode("utf-8", errors="replace")
                        except Exception:
                            pass

                    findings.append({
                        "type": "SSRF - Interactsh Callback Confirmed",
                        "evidence": f"Callback {protocol.upper()} interaction recorded via interact.sh ({full_id})",
                        "how_found": f"Injected interactsh URL into parameter '{param}' and observed callback",
                        "severity": "critical",
                        "payload": callback_url,
                        "evidence_url": test_url,
                        "evidence_body": body[:500],
                        "evidence_headers": headers,
                        "evidence_status": status,
                        "test_param": param,
                        "callback_marker": marker,
                        "callback_domain": full_id,
                        "verification_method": "interactsh_callback",
                        "interaction": interaction,
                        "raw_callback_request": raw_request,
                    })

                    logger.warning(
                        "🔥 CONFIRMED SSRF via interact.sh: %s param '%s'", url, param
                    )

                elif callback_url in body or marker in body:
                    logger.debug(
                        "SSRF candidate on %s param '%s': reflection but no callback", url, param
                    )
                    findings.append({
                        "type": "Potential SSRF - Reflection Only",
                        "evidence": f"Parameter '{param}' reflects payload but no callback received",
                        "how_found": "Payload reflected; manual verification required",
                        "severity": "low",
                        "payload": callback_url,
                        "evidence_url": test_url,
                        "test_param": param,
                        "callback_marker": marker,
                        "verification_method": "reflection_only",
                        "confidence": "low",
                    })

            except asyncio.TimeoutError:
                logger.debug(f"Timeout testing SSRF on {test_url}")
                continue
            except Exception as e:
                logger.debug(f"Error testing SSRF on {test_url}: {e}")
                continue

    except Exception as e:
        logger.exception("ssrf_oob_detector error for %s: %s", url, e)

    return findings


# Manual verification helper
def generate_manual_verification_payload(url: str, param: str) -> dict:
    """
    Generate manual verification instructions for SSRF testing.

    Usage:
        payload = generate_manual_verification_payload("https://example.com", "url")
        print(payload["instructions"])
    """
    # Use your own Burp Collaborator or interact.sh subdomain
    collaborator_domain = "YOUR_SUBDOMAIN.oastify.com"  # Replace with your domain

    callback_url = f"http://{collaborator_domain}"

    parsed = urlparse(url)
    existing_qs = parse_qs(parsed.query, keep_blank_values=True)
    new_qs = dict(existing_qs)
    new_qs[param] = [callback_url]
    test_query = urlencode(new_qs, doseq=True)
    test_url = parsed._replace(query=test_query).geturl()

    return {
        "test_url": test_url,
        "callback_url": callback_url,
        "parameter": param,
        "instructions": f"""
Manual SSRF Verification:

1. Set up DNS callback service:
   - Use Burp Collaborator: https://portswigger.net/burp/documentation/desktop/tools/collaborator
   - Or use interact.sh: curl https://interact.sh/register
   - Get your unique domain (e.g., abc123.oastify.com)

2. Replace callback URL in test:
   Original: {callback_url}
   Replace with your domain

3. Send request:
   curl "{test_url}"

4. Check for DNS callback:
   - Burp Collaborator: Check "Collaborator client" for interactions
   - interact.sh: Poll for DNS queries to your domain

5. If DNS callback received:
   ✅ CONFIRMED SSRF vulnerability

6. If no callback:
   ❌ False positive (reflection only, not SSRF)
"""
    }

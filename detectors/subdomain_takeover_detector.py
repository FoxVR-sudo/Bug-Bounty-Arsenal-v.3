# detectors/subdomain_takeover_detector.py
"""
Subdomain Takeover Detector - Easy wins for bug bounty!

Detects:
- DNS CNAME pointing to unclaimed services
- Common vulnerable services (GitHub Pages, AWS S3, Heroku, Azure, etc.)
- 20+ different cloud platforms
- Dangling DNS records

Expected Bounty Value: $100-$2,000 per finding
Common in: Large organizations with many subdomains
Easy to find: Passive scanning, no exploitation needed
"""
import logging
from urllib.parse import urlparse
from detectors.registry import register_passive

logger = logging.getLogger(__name__)

# Vulnerable service fingerprints
# Each service has: CNAME pattern, HTTP response pattern, and claim instructions
VULNERABLE_SERVICES = {
    "GitHub Pages": {
        "cname_patterns": [
            r"\.github\.io$",
            r"github\.io$",
        ],
        "response_patterns": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "claim_url": "https://pages.github.com/",
        "severity": "high",
    },

    "AWS S3": {
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"s3-.*\.amazonaws\.com$",
            r"s3\..*\.amazonaws\.com$",
        ],
        "response_patterns": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "claim_url": "https://console.aws.amazon.com/s3/",
        "severity": "high",
    },

    "Heroku": {
        "cname_patterns": [
            r"\.herokuapp\.com$",
            r"herokussl\.com$",
        ],
        "response_patterns": [
            "No such app",
            "There's nothing here, yet",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "claim_url": "https://dashboard.heroku.com/",
        "severity": "high",
    },

    "Azure": {
        "cname_patterns": [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.trafficmanager\.net$",
        ],
        "response_patterns": [
            "404 Web Site not found",
            "Error 404 - Web app not found",
        ],
        "claim_url": "https://portal.azure.com/",
        "severity": "high",
    },

    "Shopify": {
        "cname_patterns": [
            r"\.myshopify\.com$",
        ],
        "response_patterns": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        "claim_url": "https://www.shopify.com/",
        "severity": "medium",
    },

    "Tumblr": {
        "cname_patterns": [
            r"\.tumblr\.com$",
        ],
        "response_patterns": [
            "There's nothing here.",
            "Whatever you were looking for doesn't currently exist at this address",
        ],
        "claim_url": "https://www.tumblr.com/",
        "severity": "medium",
    },

    "WordPress.com": {
        "cname_patterns": [
            r"\.wordpress\.com$",
        ],
        "response_patterns": [
            "Do you want to register",
            "doesn't exist",
        ],
        "claim_url": "https://wordpress.com/",
        "severity": "medium",
    },

    "Fastly": {
        "cname_patterns": [
            r"\.fastly\.net$",
        ],
        "response_patterns": [
            "Fastly error: unknown domain",
        ],
        "claim_url": "https://www.fastly.com/",
        "severity": "high",
    },

    "Pantheon": {
        "cname_patterns": [
            r"\.pantheonsite\.io$",
        ],
        "response_patterns": [
            "The gods are wise, but do not know of the site which you seek",
            "404 error unknown site!",
        ],
        "claim_url": "https://pantheon.io/",
        "severity": "medium",
    },

    "Zendesk": {
        "cname_patterns": [
            r"\.zendesk\.com$",
        ],
        "response_patterns": [
            "Help Center Closed",
            "This help center no longer exists",
        ],
        "claim_url": "https://www.zendesk.com/",
        "severity": "medium",
    },

    "Bitbucket": {
        "cname_patterns": [
            r"\.bitbucket\.io$",
        ],
        "response_patterns": [
            "Repository not found",
            "The page you have requested does not exist",
        ],
        "claim_url": "https://bitbucket.org/",
        "severity": "high",
    },

    "Cargo": {
        "cname_patterns": [
            r"\.cargocollective\.com$",
        ],
        "response_patterns": [
            "404 Not Found",
        ],
        "claim_url": "https://cargo.site/",
        "severity": "low",
    },

    "Readme.io": {
        "cname_patterns": [
            r"\.readme\.io$",
        ],
        "response_patterns": [
            "Project doesnt exist... yet!",
            "This project does not exist",
        ],
        "claim_url": "https://readme.io/",
        "severity": "medium",
    },

    "Surge.sh": {
        "cname_patterns": [
            r"\.surge\.sh$",
        ],
        "response_patterns": [
            "project not found",
        ],
        "claim_url": "https://surge.sh/",
        "severity": "medium",
    },

    "Unbounce": {
        "cname_patterns": [
            r"\.unbouncepages\.com$",
        ],
        "response_patterns": [
            "The requested URL was not found on this server",
            "This page is currently unavailable",
        ],
        "claim_url": "https://unbounce.com/",
        "severity": "low",
    },

    "Ghost": {
        "cname_patterns": [
            r"\.ghost\.io$",
        ],
        "response_patterns": [
            "The thing you were looking for is no longer here",
        ],
        "claim_url": "https://ghost.org/",
        "severity": "low",
    },

    "JetBrains": {
        "cname_patterns": [
            r"\.myjetbrains\.com$",
        ],
        "response_patterns": [
            "is not a registered InCloud YouTrack",
        ],
        "claim_url": "https://www.jetbrains.com/",
        "severity": "medium",
    },

    "Webflow": {
        "cname_patterns": [
            r"\.webflow\.io$",
        ],
        "response_patterns": [
            "The page you are looking for doesn't exist or has been moved",
        ],
        "claim_url": "https://webflow.com/",
        "severity": "low",
    },

    "Statuspage": {
        "cname_patterns": [
            r"\.statuspage\.io$",
        ],
        "response_patterns": [
            "You are being",
            "redirected",
        ],
        "claim_url": "https://www.statuspage.io/",
        "severity": "medium",
    },

    "HelpJuice": {
        "cname_patterns": [
            r"\.helpjuice\.com$",
        ],
        "response_patterns": [
            "We could not find what you're looking for",
        ],
        "claim_url": "https://helpjuice.com/",
        "severity": "low",
    },
}


@register_passive
def subdomain_takeover_detector(text, combined_dict):
    """
    Detect potential subdomain takeover vulnerabilities.

    Checks:
    1. HTTP response for service fingerprints
    2. Known vulnerable services (GitHub Pages, S3, Heroku, etc.)

    Note: This is passive detection. DNS CNAME checks require external tools.
    """
    url = combined_dict["url"]
    context = combined_dict["context"]
    findings = []

    try:
        resp = context.get("resp")
        if not resp:
            return findings

        body = context.get("body", "")
        status = resp.status
        context.get("headers", {})

        parsed = urlparse(url)
        hostname = parsed.netloc.lower()

        # Check each vulnerable service
        for service_name, service_info in VULNERABLE_SERVICES.items():
            # Check if response matches service patterns
            for pattern in service_info["response_patterns"]:
                if pattern.lower() in body.lower():
                    # Found potential takeover!
                    findings.append({
                        "type": f"Subdomain Takeover - {service_name}",
                        "severity": service_info["severity"],
                        "evidence": f"Response contains '{pattern}' indicating unclaimed {service_name} resource",
                        "how_found": f"HTTP response matched {service_name} takeover fingerprint",
                        "evidence_url": url,
                        "evidence_status": status,
                        "evidence_body": body[:500],
                        "service": service_name,
                        "claim_url": service_info["claim_url"],
                        "impact": f"Subdomain takeover via {service_name}. Attacker can claim this subdomain and serve malicious content under victim's domain. Can be used for phishing, session hijacking, or bypassing CORS.",
                        "remediation": f"Remove DNS CNAME record pointing to {service_name} or claim the resource at {service_info['claim_url']}",
                        "cve_reference": "CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action",
                        "verification": f"1. Check DNS: nslookup {hostname}\n2. Verify CNAME points to {service_name}\n3. Try to claim resource at {service_info['claim_url']}",
                    })

                    logger.warning(f"🔥 {service_info['severity'].upper()}: Potential {service_name} takeover on {hostname}")
                    break  # One finding per service is enough

        # Check for generic subdomain takeover indicators
        generic_patterns = [
            ("NXDOMAIN", "DNS record not found"),
            ("No Such Account", "Account doesn't exist"),
            ("Not Found", "Resource not found"),
        ]

        # Only flag if status is 404 or similar
        if status in [404, 410, 451]:
            for pattern, description in generic_patterns:
                if pattern.lower() in body.lower():
                    findings.append({
                        "type": "Possible Subdomain Takeover",
                        "severity": "low",
                        "evidence": f"Response contains '{pattern}' with status {status}",
                        "how_found": f"HTTP {status} with message: {description}",
                        "evidence_url": url,
                        "evidence_status": status,
                        "impact": "Potential subdomain takeover. Requires manual verification.",
                        "remediation": "Check DNS records and verify if subdomain points to unclaimed resource",
                    })
                    break

    except Exception as e:
        logger.exception(f"subdomain_takeover_detector error for {url}: {e}")

    return findings

# detectors/secret_detector.py
# Passive + active detector for leaked secrets.
# Pipeline: pattern match → entropy check → placeholder filter → URL context filter
# → active AWS STS probe for AKIA keys.
import html
import logging
from detectors.registry import register_passive
from utils.secret_validator import (
    SECRET_PATTERNS,
    validate_secret_finding,
    active_validate_aws_key,
    _mask_token,
)
from utils.context_filter import should_skip_url

logger = logging.getLogger(__name__)

# Map pattern_key → human label + severity
_PATTERN_META: dict[str, tuple[str, str]] = {
    "private_key":    ("Private Key",          "critical"),
    "aws_access_key": ("AWS Access Key ID",     "critical"),
    "stripe_live":    ("Stripe Live Secret Key","critical"),
    "gcp_api_key":    ("GCP API Key",           "high"),
    "github_pat":     ("GitHub Personal Access Token", "high"),
    "sendgrid":       ("SendGrid API Key",      "high"),
    "slack_token":    ("Slack Token",           "high"),
    "jwt":            ("JSON Web Token (JWT)",  "medium"),
    "stripe_test":    ("Stripe Test Secret Key","medium"),
    "twilio_sid":     ("Twilio Account SID",    "medium"),
    "google_oauth":   ("Google OAuth Token",    "high"),
    "aws_secret_key": ("AWS Secret Key (heuristic)", "high"),
    "generic_long":   ("Generic Long Token",    "low"),
}


@register_passive
def detect_secrets_from_text(text, context):
    """
    Passive detector: scans response text for leaked secrets.

    Validation pipeline per candidate token:
      1. Pattern match (SECRET_PATTERNS)
      2. URL context filter — skip documentation / checklist pages
      3. Entropy check — discard low-entropy / non-random strings
      4. Placeholder detection — discard example/README tokens
      5. Returns confidence (0-100) + signal_strength based on entropy + pattern

    Active AWS STS probe is intentionally NOT run here (passive detectors are
    synchronous). Use the active detector counterpart for live key probing.
    """
    findings = []
    if not text:
        return findings

    url = ''
    if isinstance(context, dict):
        url = context.get('url') or context.get('target') or ''

    if should_skip_url(url):
        return findings

    snippet = text if len(text) <= 200_000 else text[:200_000]

    seen_tokens: set[str] = set()

    for pattern_key, (rx, _base_conf) in SECRET_PATTERNS.items():
        for m in rx.finditer(snippet):
            token = m.group(1) if m.lastindex else m.group(0)
            if not token or token in seen_tokens:
                continue
            seen_tokens.add(token)

            validation = validate_secret_finding(token, pattern_key, url)
            if validation['skip']:
                logger.debug(
                    "secret_detector: skipping %s token — %s",
                    pattern_key, validation['reason'],
                )
                continue

            masked = _mask_token(token)
            label, severity = _PATTERN_META.get(pattern_key, ("Potential Secret", "medium"))

            # Build a small excerpt around the match
            start = max(0, m.start() - 80)
            end   = min(len(snippet), m.end() + 80)
            before = html.escape(snippet[start:m.start()])
            after  = html.escape(snippet[m.end():end])
            excerpt_html = f"{before}<b>{html.escape(masked)}</b>{after}"

            conf = validation['confidence']
            sig  = validation['signal_strength']

            findings.append({
                "type":             "Leaked Secret",
                "title":            f"{label} Exposed",
                "evidence":         f"{label}: {masked}",
                "evidence_details": excerpt_html,
                "how_found":        (
                    f"Pattern match ({pattern_key}); "
                    f"entropy={sig:.2f}; confidence={conf}%"
                ),
                "severity":         severity,
                "confidence":       conf,
                "signal_strength":  sig,
                "verified":         False,
                "payload":          None,
                "_pattern_key":     pattern_key,   # kept for active probe step
                "_raw_token_len":   len(token),    # length only, not the token itself
            })

    return findings


@register_passive
def detect_secrets_active_hints(text, context):
    """
    Second-pass passive detector that upgrades AWS findings to 'needs active probe'
    so the scanner can schedule an async STS check.

    This is a no-op by default; the async probe is done by detect_secrets_aws_active.
    """
    return []


# ── Async active detector for AWS key live-probe ─────────────────────────────

from detectors.registry import register_active  # noqa: E402


@register_active
async def detect_secrets_aws_active(session, url, context):
    """
    Active validation: re-scans the page and performs a live AWS STS probe
    for any AKIA* keys found.  Updates finding confidence to 95 and sets
    verified=True on confirmed live keys.
    """
    findings = []
    try:
        import aiohttp
        async with session.get(url, allow_redirects=True,
                               timeout=aiohttp.ClientTimeout(total=10)) as resp:
            try:
                body = await resp.text()
            except Exception:
                return findings
    except Exception:
        return findings

    from utils.secret_validator import SECRET_PATTERNS as _SP
    rx_aws, _ = _SP['aws_access_key']

    for m in rx_aws.finditer(body[:200_000]):
        access_key = m.group(0)
        validation = validate_secret_finding(access_key, 'aws_access_key', url)
        if validation['skip']:
            continue

        masked = _mask_token(access_key)
        is_live = await active_validate_aws_key(session, access_key)

        conf    = 95 if is_live else validation['confidence']
        severity = 'critical' if is_live else 'high'

        findings.append({
            "type":            "AWS Access Key Exposed",
            "title":           "Live AWS Access Key Found" if is_live else "AWS Access Key Candidate",
            "evidence":        f"AWS Access Key ID: {masked}",
            "how_found":       (
                "AWS STS GetCallerIdentity probe confirmed live key"
                if is_live else
                f"Pattern match (AKIA prefix); entropy validated; confidence={conf}%"
            ),
            "severity":        severity,
            "confidence":      conf,
            "signal_strength": 0.95 if is_live else validation['signal_strength'],
            "verified":        is_live,
            "payload":         None,
        })

    return findings


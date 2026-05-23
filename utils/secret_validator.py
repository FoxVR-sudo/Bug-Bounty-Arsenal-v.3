"""
utils/secret_validator.py
─────────────────────────
Real secret validation pipeline:
  1. Shannon entropy check  — rejects low-entropy strings (not random → not a key)
  2. Known-pattern matching — per-type confidence baselines
  3. Placeholder detection  — catches YOUR_API_KEY, REPLACE_ME, etc.
  4. Active AWS STS probe   — validates AWS AKIA keys without needing the secret
  5. signal_strength        — 0.0–1.0 composite score used by scoring.py
"""

import math
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Shannon Entropy ────────────────────────────────────────────────────────────

def entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    length = len(s)
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ── Known-pattern registry (pattern, base_confidence 0-100) ────────────────────

SECRET_PATTERNS: dict[str, tuple[re.Pattern, int]] = {
    # Highest confidence — very specific prefixes
    "private_key":   (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), 99),
    "aws_access_key": (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 95),
    "stripe_live":   (re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b'), 98),
    "gcp_api_key":   (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), 92),
    "github_pat":    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'), 95),
    "sendgrid":      (re.compile(r'\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b'), 95),
    "slack_token":   (re.compile(r'\bxox[pabo]-[A-Za-z0-9\-]{8,}\b'), 90),

    # High — well-structured but shorter prefix
    "jwt":           (re.compile(r'\bey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'), 85),
    "stripe_test":   (re.compile(r'\bsk_test_[0-9a-zA-Z]{24,}\b'), 80),
    "twilio_sid":    (re.compile(r'\bAC[a-z0-9]{32}\b'), 82),
    "google_oauth":  (re.compile(r'\b1//[A-Za-z0-9_\-]{38}\b'), 88),

    # Medium — heuristic / length-based
    "aws_secret_key":  (re.compile(r'\b[A-Za-z0-9/+=]{40}\b'), 55),
    "generic_long":    (re.compile(r'\b[A-Za-z0-9\-_/+=]{32,128}\b'), 40),
}

# Pattern that this key ID matched (used to select active probe)
_PATTERN_ORDER = list(SECRET_PATTERNS.keys())


# ── Placeholder / example-token detection ─────────────────────────────────────

_PLACEHOLDER_RE = re.compile(
    r'your[_\-]?(?:api[_\-]?)?(?:key|secret|token)'
    r'|replace[_\-]?(?:me|with|this)?'
    r'|insert[_\-]?your'
    r'|<your[_\s]'
    r'|example[_\-]?key'
    r'|\bfoo\b|\bbar\b|\btest\b|\bdemo\b'
    r'|xxxxxxxx|aaaa{4,}|0{8,}|1{8,}',
    re.I,
)


def _is_placeholder(token: str) -> bool:
    """Return True if the token looks like a documentation placeholder."""
    if _PLACEHOLDER_RE.search(token):
        return True
    # Too few unique characters → repeated/not random
    if len(token) > 8 and len(set(token.lower())) < 5:
        return True
    return False


# ── URL / context false-positive filter ───────────────────────────────────────

_FP_URL_RE = re.compile(
    r'/(?:readme|contributing|changelog|license|install|setup|tutorial|guide'
    r'|docs?|wiki|blog|faq|help|about|example|sample|placeholder|checklist'
    r'|roadmap|getting[_\-]started)(?:\b|[/_\-])'
    r'|\.(md|txt|rst|adoc)(?:\?.*)?$'
    r'|github\.com/[^/]+/[^/]+/(?:blob|tree)/.+\.(?:md|txt|rst)',
    re.I,
)


def is_documentation_url(url: str) -> bool:
    """Return True if the URL looks like documentation, a blog, or a checklist page."""
    return bool(_FP_URL_RE.search(url or ''))


# ── Signal strength composite ─────────────────────────────────────────────────

def compute_signal_strength(token: str, pattern_key: Optional[str] = None) -> float:
    """
    Returns a signal_strength in [0.0, 1.0].

    Algorithm:
      base  = per-pattern confidence (0–100) / 100
      bonus = entropy bonus (+0.15 if ent ≥ 4.5, +0.07 if ent ≥ 3.5)
      If low entropy and not a high-specificity pattern → penalty
    """
    if _is_placeholder(token):
        return 0.05

    base_conf = SECRET_PATTERNS.get(pattern_key or '', (None, 40))[1] / 100.0
    ent = entropy(token)

    # Entropy gate: tokens shorter than 10 chars get a pass; longer ones must have
    # reasonable randomness.
    if len(token) >= 10 and ent < 3.0:
        # Very low entropy → probably not a real key
        # Exception: fixed-prefix patterns (aws, stripe, gcp) already verified by regex
        high_spec = {'aws_access_key', 'stripe_live', 'stripe_test', 'gcp_api_key', 'github_pat',
                     'sendgrid', 'slack_token', 'private_key', 'twilio_sid'}
        if pattern_key not in high_spec:
            return max(0.05, base_conf * 0.3)

    entropy_bonus = 0.0
    if ent >= 4.5:
        entropy_bonus = 0.15
    elif ent >= 3.5:
        entropy_bonus = 0.07

    return min(1.0, base_conf + entropy_bonus)


# ── Main validation entry point ────────────────────────────────────────────────

def validate_secret_finding(token: str, pattern_key: str, url: str = '') -> dict:
    """
    Validate a single candidate secret.

    Returns:
        {
          "skip":           bool,   # discard this finding entirely
          "verified":       bool,   # True only after active probe confirms live key
          "signal_strength": float, # 0.0–1.0
          "confidence":     int,    # 0–100
          "reason":         str,    # human-readable explanation
        }
    """
    if is_documentation_url(url):
        return {
            "skip": True, "verified": False, "signal_strength": 0.0,
            "confidence": 5, "reason": "documentation/checklist URL",
        }

    if _is_placeholder(token):
        return {
            "skip": True, "verified": False, "signal_strength": 0.05,
            "confidence": 5, "reason": "placeholder / example token",
        }

    sig = compute_signal_strength(token, pattern_key)
    conf = int(min(100, sig * 100))

    if conf < 15:
        return {
            "skip": True, "verified": False, "signal_strength": sig,
            "confidence": conf,
            "reason": f"low signal (entropy={entropy(token):.2f}, pattern={pattern_key})",
        }

    return {
        "skip": False, "verified": False, "signal_strength": sig,
        "confidence": conf,
        "reason": f"pattern={pattern_key}, entropy={entropy(token):.2f}, signal={sig:.2f}",
    }


# ── Active AWS STS probe ───────────────────────────────────────────────────────

async def active_validate_aws_key(session, access_key: str) -> bool:
    """
    Probe the AWS STS GetCallerIdentity endpoint with only the access key ID
    (no secret required).

    A *valid* key ID with a missing/wrong secret returns HTTP 403 with body containing
    'SignatureDoesNotMatch'.  An *invalid* key ID returns HTTP 400 with
    'InvalidClientTokenId'.

    Returns True if the key appears to be a live (but not necessarily authorised)
    AWS credential.  Does NOT make any mutating calls.
    """
    import aiohttp
    url = 'https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15'
    headers = {
        # Intentionally malformed Authorization so AWS rejects the signature but
        # still validates the key ID.
        'Authorization': f'AWS4-HMAC-SHA256 Credential={access_key}//sts/aws4_request, '
                         'SignedHeaders=host, Signature=00000000',
        'x-amz-date': '20000101T000000Z',
    }
    try:
        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=6),
            allow_redirects=False,
        ) as resp:
            body = await resp.text()
            if resp.status == 403 and 'SignatureDoesNotMatch' in body:
                logger.info("AWS key %s... is LIVE (STS probe: SignatureDoesNotMatch)", access_key[:8])
                return True
            # 400 + InvalidClientTokenId → key does not exist
            return False
    except Exception as exc:
        logger.debug("AWS STS probe failed for %s...: %s", access_key[:8], exc)
        return False


# ── Helpers exposed to other modules ──────────────────────────────────────────

def match_all_patterns(text: str) -> list[dict]:
    """
    Run all SECRET_PATTERNS against *text*.
    Returns list of {pattern_key, token, base_confidence}.
    """
    results = []
    for key, (rx, base_conf) in SECRET_PATTERNS.items():
        for m in rx.finditer(text):
            token = m.group(1) if m.lastindex else m.group(0)
            results.append({"pattern_key": key, "token": token, "base_confidence": base_conf})
    return results


def _mask_token(token: str) -> str:
    """Mask a secret token for safe display, preserving first/last 4 chars."""
    if not token:
        return token
    n = len(token)
    if n <= 8:
        return token[0] + "*" * max(0, n - 2) + token[-1] if n > 2 else "*" * n
    return token[:4] + "*" * (n - 8) + token[-4:]

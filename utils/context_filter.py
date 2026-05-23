"""
utils/context_filter.py
───────────────────────
Filters out findings that are almost certainly false positives based on:
  - URL context  (documentation, README, blog, checklist pages)
  - Response content signals (placeholder text in the page)
  - Finding-level metadata (confidence below threshold on noisy pages)

Usage:
    from utils.context_filter import filter_findings, should_skip_url

    # Drop entire URL if it's documentation
    if should_skip_url(url):
        return []

    # Filter a list of findings, applying all heuristics
    findings = filter_findings(findings, url=url, response_body=body)
"""

import re
from typing import List, Dict, Any

# ── URL patterns that indicate non-application content ────────────────────────

_DOC_URL_RE = re.compile(
    r'/(?:readme|contributing|changelog|license|install|setup|tutorial|guide'
    r'|docs?|wiki|blog|faq|help|about|example|sample|placeholder|checklist'
    r'|roadmap|getting[_\-]started|quickstart|howto|reference|api[_\-]reference'
    r'|support|release[_\-]notes?)(?:\b|[/_\-])'
    r'|\.(md|txt|rst|adoc|pdf)(?:\?.*)?$'
    r'|github\.com/[^/]+/[^/]+/(?:blob|tree)/.+\.(?:md|txt|rst)'
    r'|/static/|/assets/|/vendor/|/node_modules/',
    re.I,
)

# Domains that are almost always documentation/reference sites
_DOC_DOMAINS_RE = re.compile(
    r'\b(?:docs\.|developer\.|developers\.|man\.|readthedocs\.io|gitbook\.io'
    r'|confluence\.|notion\.so|medium\.com|dev\.to|hashnode\.com)\b',
    re.I,
)


def should_skip_url(url: str) -> bool:
    """
    Return True if this URL is likely documentation or non-application content
    that should be excluded from vulnerability scanning.
    """
    if not url:
        return False
    return bool(_DOC_URL_RE.search(url) or _DOC_DOMAINS_RE.search(url))


# ── Response-body signals indicating placeholder/example content ──────────────

_PLACEHOLDER_BODY_RE = re.compile(
    r'your[_\-]?(?:api[_\-]?)?(?:key|secret|token)'
    r'|replace[_\-]?(?:me|with|this)?'
    r'|insert[_\-]?your'
    r'|<your[_\s]'
    r'|example[_\-]?key'
    r'|example\.com/api'
    r'|REPLACE_ME'
    r'|INSERT_YOUR'
    r'|# TODO: add key'
    r'|\$\{[A-Z_]+\}'        # shell variable placeholders like ${API_KEY}
    r'|\{\{[A-Z_a-z]+\}\}',  # template placeholders like {{apiKey}}
    re.I,
)

_MIN_PLACEHOLDER_SIGNALS = 2  # need at least this many matches to flag page as "template"


def _is_placeholder_page(body: str) -> bool:
    """Return True if the response body contains enough placeholder signals."""
    if not body:
        return False
    return len(_PLACEHOLDER_BODY_RE.findall(body[:50_000])) >= _MIN_PLACEHOLDER_SIGNALS


# ── Main filter ───────────────────────────────────────────────────────────────

def filter_findings(
    findings: List[Dict[str, Any]],
    url: str = '',
    response_body: str = '',
    *,
    min_confidence_on_doc_page: int = 50,
) -> List[Dict[str, Any]]:
    """
    Remove findings that are likely false positives.

    Rules applied in order:
      1. If the URL is documentation → drop all findings.
      2. If the response body looks like a template/placeholder page →
         drop findings with confidence below *min_confidence_on_doc_page*.
      3. Findings explicitly marked skip=True are dropped.

    Args:
        findings:                  Raw findings list from a detector.
        url:                       The URL that was scanned.
        response_body:             Raw response text (used for body-signal checks).
        min_confidence_on_doc_page: Confidence threshold applied on template pages.

    Returns:
        Filtered findings list.
    """
    if not findings:
        return findings

    if should_skip_url(url):
        return []

    is_template_page = _is_placeholder_page(response_body)

    result = []
    for finding in findings:
        # Respect explicit skip flag (set by secret_validator)
        if finding.get('skip'):
            continue

        # On template/placeholder pages, only keep high-confidence findings
        if is_template_page:
            conf = finding.get('confidence')
            # conf may be int (0-100) or string ('low'/'medium'/'high')
            if isinstance(conf, int) and conf < min_confidence_on_doc_page:
                continue
            if isinstance(conf, str) and conf.lower() in ('low', 'very low'):
                continue

        result.append(finding)

    return result


# ── Differential analysis helper ──────────────────────────────────────────────

def differential_check(
    baseline_body: str,
    test_body: str,
    marker: str,
) -> dict:
    """
    Compare a baseline response against a test response to detect if a
    specific marker (payload/inject marker) appears only in the test response.

    Returns:
        {
          "reflected":    bool,  # marker found in test but not baseline
          "new_content":  bool,  # test body is meaningfully different from baseline
          "confidence_boost": int,  # suggested confidence boost (0–25)
        }
    """
    if not test_body:
        return {"reflected": False, "new_content": False, "confidence_boost": 0}

    reflected = (marker in test_body) and (marker not in (baseline_body or ''))

    # Rough measure of how different the responses are
    baseline_len = len(baseline_body or '')
    test_len = len(test_body)
    len_diff = abs(test_len - baseline_len)
    new_content = len_diff > max(50, baseline_len * 0.05)

    confidence_boost = 0
    if reflected:
        confidence_boost += 20
    if new_content and reflected:
        confidence_boost += 5

    return {
        "reflected": reflected,
        "new_content": new_content,
        "confidence_boost": confidence_boost,
    }

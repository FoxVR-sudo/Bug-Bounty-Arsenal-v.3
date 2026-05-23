import re
from detectors.registry import register_passive


@register_passive
def csrf_detector_from_text(text, context):
    findings = []
    if not text:
        return findings

    forms = re.findall(r'(<form\b.*?>.*?</form>)', text, re.IGNORECASE | re.DOTALL)
    for form in forms:
        if not re.search(r'name=["\'](csrf_token|_csrf|authenticity_token|csrf)[\'"]', form, re.IGNORECASE):
            findings.append({
                "type": "Missing CSRF Token",
                "evidence": "Form without typical CSRF hidden input found",
                "evidence_details": form,  # ново поле с HTML на формата
                "how_found": "Passive analysis of HTML forms",
                "severity": "low",
                "payload": None,
                "screenshot_path": None  # ново поле, ще се попълва по-късно
            })
    return findings

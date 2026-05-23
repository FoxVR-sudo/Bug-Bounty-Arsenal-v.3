# detectors/sql_pattern_detector.py
# Passive detector: анализира response text.
import re
from detectors.registry import register_passive

__all__ = ['detect_sql_from_text']


@register_passive
def detect_sql_from_text(text, context):
    """
    Пассивен детектор за SQL-индикатори.
    Връща list[dict].
    """
    patterns = [
        (r"you have an error in your sql syntax", "MySQL syntax error"),
        (r"warning: mysql", "MySQL warning"),
        (r"unclosed quotation mark after the character string", "MSSQL unclosed quote"),
        (r"quoted string not properly terminated", "Oracle quoted string not terminated"),
        (r"pg_query\(", "Postgres pg_query"),
        (r"SQLSTATE\[HY000\]", "PDO SQLSTATE"),
        (r"sqlite error", "SQLite error"),
    ]

    findings = []
    if not text:
        return findings

    for pat, name in patterns:
        if re.search(pat, text, re.IGNORECASE):
            findings.append({
                "type": "SQL Injection Indicator",
                "evidence": name,
                "how_found": f"Matched pattern {pat}",
                "severity": "high",
                "payload": None
            })
    return findings

#!/usr/bin/env python3
# tools/mask_and_extract_evidence.py
# Generate masked evidence report + masked sample raw_responses for attachment.
# Reads raw response files created by scanner in the reports directory.
import os
import re
import json
import html
import argparse
from pathlib import Path

REPORTS_DIR = "reports"
ATTACH_DIR = os.path.join(REPORTS_DIR, "attachments")
OUTPUT_JSON = os.path.join(REPORTS_DIR, "masked_evidence_report.json")
OUTPUT_HTML = os.path.join(REPORTS_DIR, "masked_evidence_report.html")

PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("GCP API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("JWT", re.compile(r"\b(eyJ[A-Za-z0-9_\-\.]+=*)\b")),
    ("Slack Token", re.compile(r"\b(xox[pabo]-?[A-Za-z0-9-]{8,})\b")),
    ("Stripe Secret Key", re.compile(r"\b(sk_live|sk_test)_[0-9a-zA-Z]{24,}\b")),
    ("Azure AccountKey", re.compile(r"AccountKey=([A-Za-z0-9\+\/=]+)")),
    ("Generic long token", re.compile(r"\b([A-Za-z0-9\-_\/+=]{32,128})\b")),
]

WHITELIST_DEFAULT = ("http", "https", "www", ".com", ".org", "localhost")


def mask_token(token: str) -> str:
    if not token:
        return token
    n = len(token)
    if n <= 8:
        return token[0] + "*" * max(0, n-2) + token[-1] if n > 2 else "*" * n
    return token[:4] + "*" * (n-8) + token[-4:]


def parse_raw_response(path: Path):
    try:
        data = path.read_bytes()
    except Exception:
        return None, None
    try:
        parts = data.split(b"\n\n", 1)
        meta = json.loads(parts[0].decode("utf-8", errors="replace"))
        body = parts[1].decode("utf-8", errors="replace") if len(parts) > 1 else ""
        return meta, body
    except Exception:
        return None, data.decode("utf-8", errors="replace")


def ensure_dirs():
    os.makedirs(ATTACH_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)


def scan_and_mask(whitelist=None, blacklist=None):
    whitelist = whitelist or list(WHITELIST_DEFAULT)
    blacklist = blacklist or []
    ensure_dirs()
    findings = []

    for root, dirs, files in os.walk(REPORTS_DIR):
        if os.path.abspath(root).startswith(os.path.abspath(ATTACH_DIR)):
            continue
        for fname in files:
            if not fname.endswith(".txt"):
                continue
            full = Path(root) / fname
            meta, body = parse_raw_response(full)
            if body is None:
                continue
            snippet = body[:200000]
            matches = []
            for label, rx in PATTERNS:
                for m in rx.finditer(snippet):
                    token = m.group(1) if m.groups() else m.group(0)
                    if not token:
                        continue
                    lowtoken = token.lower()
                    if any(w in lowtoken for w in whitelist):
                        continue
                    if blacklist and not any(b.lower() in lowtoken for b in blacklist):
                        continue
                    masked = mask_token(token)
                    before = html.escape(snippet[max(0, m.start()-80):m.start()])
                    after = html.escape(snippet[m.end():m.end()+80])
                    excerpt = f"{before}<b>{html.escape(masked)}</b>{after}"
                    matches.append({"type": label, "masked": masked, "excerpt": excerpt})
            if matches:
                attach_name = f"masked_{fname}"
                attach_path = Path(ATTACH_DIR) / attach_name
                # write minimal excerpt file (safe)
                try:
                    attach_path.write_text(html.unescape(matches[0]["excerpt"] if matches else snippet[:500]), encoding="utf-8")
                except Exception:
                    pass

                # Mask headers (meta) for inclusion (best-effort)
                masked_meta = {}
                if meta:
                    masked_meta = dict(meta)
                    headers = masked_meta.get("headers") or {}
                    try:
                        headers_s = json.dumps(headers)
                        for label, rx in PATTERNS:
                            for mm in rx.finditer(headers_s):
                                token = mm.group(1) if mm.groups() else mm.group(0)
                                if token and not any(w in token.lower() for w in whitelist):
                                    headers_s = headers_s.replace(token, mask_token(token))
                        masked_meta["headers"] = json.loads(headers_s)
                    except Exception:
                        pass

                findings.append({
                    "source_file": str(full),
                    "meta": masked_meta,
                    "matches": matches,
                    "attachment": str(attach_path),
                })

    # write JSON + HTML
    try:
        with open(OUTPUT_JSON, "w", encoding="utf-8") as jf:
            json.dump(findings, jf, ensure_ascii=False, indent=2)
    except Exception:
        pass

    html_parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>Masked Evidence Report</title></head><body>",
        "<h1>Masked Evidence Report</h1>"
    ]
    for f in findings:
        html_parts.append("<div style='border:1px solid #ccc;padding:10px;margin:10px;'>")
        html_parts.append(f"<strong>Source:</strong> {html.escape(f.get('source_file', ''))}<br>")
        meta = f.get("meta") or {}
        if meta:
            html_parts.append(f"<strong>URL:</strong> {html.escape(meta.get('url', ''))}<br>")
            html_parts.append(f"<strong>Status:</strong> {html.escape(str(meta.get('status', '')))}<br>")
            if meta.get("headers"):
                html_parts.append("<strong>Masked headers:</strong><pre>" + html.escape(json.dumps(meta.get("headers"), ensure_ascii=False, indent=2)) + "</pre>")
        for m in f.get("matches", []):
            html_parts.append(f"<div><strong>Type:</strong> {html.escape(m['type'])}<br>")
            html_parts.append(f"<strong>Masked:</strong> {html.escape(m['masked'])}<br>")
            html_parts.append(f"<strong>Excerpt:</strong><div style='background:#f7f7f7;padding:6px'>{m['excerpt']}</div></div>")
        if f.get("attachment"):
            rel = os.path.relpath(f.get("attachment"), os.path.dirname(OUTPUT_HTML))
            html_parts.append(f"<strong>Attachment (masked excerpt):</strong> <a href='{html.escape(rel)}'>{html.escape(os.path.basename(f.get('attachment')))}</a><br>")
        html_parts.append("</div>")
    html_parts.append("</body></html>")

    try:
        with open(OUTPUT_HTML, "w", encoding="utf-8") as hf:
            hf.write("\n".join(html_parts))
    except Exception:
        pass

    print("Masked evidence report written:")
    print(f" - JSON: {OUTPUT_JSON}")
    print(f" - HTML : {OUTPUT_HTML}")
    print(f" - Attachments dir: {ATTACH_DIR}")


def parse_args_and_run():
    ap = argparse.ArgumentParser(description="Scan reports for secrets and generate masked evidence files")
    ap.add_argument("--whitelist", "-w", help="Comma-separated whitelist substrings to ignore", default="")
    # allow --blacklist with optional value (nargs='?' makes the value optional)
    ap.add_argument("--blacklist", "-b", nargs='?', help="Comma-separated blacklist substrings (require-match). If omitted, blacklist is empty.", const="", default="")
    args = ap.parse_args()
    wl = [x.strip() for x in args.whitelist.split(",")] if args.whitelist else None
    bl = [x.strip() for x in args.blacklist.split(",")] if args.blacklist else None
    scan_and_mask(wl, bl)


if __name__ == "__main__":
    parse_args_and_run()

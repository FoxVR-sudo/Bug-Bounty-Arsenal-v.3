#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# tools/build_full_report.py
# Build a single comprehensive HTML report by aggregating scan results and correlated/masked evidence.
# This variant emits only findings with severity "high" or "critical".

import os
import json
import html
import sys
from pathlib import Path
from datetime import datetime

REPORTS_DIR = "reports"
MAIN_JSON = os.path.join(REPORTS_DIR, "report.json")
COMBINED_JSON = os.path.join(REPORTS_DIR, "combined_mapping.json")
OUT_HTML = os.path.join(REPORTS_DIR, "report_full.html")
SNIPPET_LEN = 800


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to parse JSON {path}: {e}", file=sys.stderr)
    return None


def short_snippet_from_file(path, length=SNIPPET_LEN):
    try:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read(length)
            return data
    except Exception:
        return None


def mkpre(obj):
    # Use compact JSON serialization (no indentation) which is faster and uses less memory.
    try:
        if isinstance(obj, (dict, list)):
            s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
        else:
            s = str(obj)
        return "<pre>{}</pre>".format(html.escape(s))
    except Exception:
        return "<pre>{}</pre>".format(html.escape(str(obj)))


def is_high_or_critical(finding):
    sev = (finding.get("severity") or "").lower()
    return sev in ("high", "critical")


def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)

    main_obj = load_json(MAIN_JSON)
    if main_obj is None:
        print(f"[ERROR] Main report not found or invalid: {MAIN_JSON}", file=sys.stderr)
        candidates = list(Path(REPORTS_DIR).glob("*.json"))
        if not candidates:
            print("[ERROR] No JSON files in reports/ to build report.", file=sys.stderr)
            return
        for c in candidates:
            obj = load_json(str(c))
            if obj:
                main_obj = obj
                print(f"[WARN] Using fallback JSON: {c}")
                break
        if main_obj is None:
            print("[ERROR] No usable JSON files found.", file=sys.stderr)
            return

    # normalize main_results
    if isinstance(main_obj, dict) and "results" in main_obj:
        main_results = main_obj.get("results", []) or []
    elif isinstance(main_obj, list):
        main_results = main_obj
    elif isinstance(main_obj, dict) and "metadata" in main_obj and "results" in main_obj:
        main_results = main_obj.get("results", []) or []
    else:
        main_results = main_obj if isinstance(main_obj, list) else []

    # Filter to high / critical only
    high_results = [r for r in main_results if is_high_or_critical(r)]

    combined = load_json(COMBINED_JSON) or {}
    mapping_lookup = {}
    for m in (combined.get("mappings") or []):
        for mi in (m.get("matched_main_indices") or []):
            mapping_lookup.setdefault(mi, []).append(m)

    # Stream output to file to avoid building a large in-memory list of HTML fragments.
    try:
        with open(OUT_HTML, "w", encoding="utf-8") as f:
            f.write("<!doctype html><html><head><meta charset='utf-8'><title>Critical & High Findings Report</title>")
            f.write("<meta name='viewport' content='width=device-width,initial-scale=1'/>")
            f.write("<style>")
            f.write("body{font-family:Arial,Helvetica,sans-serif;margin:0;padding:20px;color:#222;background:#f6f7f8}")
            f.write(".wrap{max-width:1200px;margin:0 auto;background:#fff;padding:20px;border-radius:8px;box-shadow:02px8px rgba(0,0,0,0.06)}")
            f.write("h1,h2,h3{margin:6px0}")
            f.write(".finding{border:1px solid #e1e1e1;padding:12px;border-radius:6px;margin:12px0;background:#fff}")
            f.write(".meta{font-size:0.9em;color:#666;margin-bottom:8px}")
            f.write("pre{background:#f7f7f7;padding:8px;border-radius:6px;overflow:auto;white-space:pre-wrap}")
            f.write(".toc{background:#fafafa;border:1px solid #eee;padding:12px;border-radius:6px;margin-bottom:12px}")
            f.write(".badge{display:inline-block;padding:4px8px;border-radius:6px;font-weight:600;margin-left:8px}")
            f.write(".high{background:#dc3545;color:#fff}.med{background:#ffc107;color:#000}.low{background:#6c757d;color:#fff}")
            f.write("</style></head><body><div class='wrap'>")
            f.write(f"<h1>Critical & High Findings Report - generated {datetime.utcnow().isoformat()} UTC</h1>")

            f.write(f"<div class='meta'><b>Total high/critical findings:</b> {len(high_results)}</div>")

            # Table of contents
            f.write("<div class='toc'><h2>Contents</h2><ol>")
            for idx, r in enumerate(high_results, start=1):
                title = html.escape((r.get("type") or "Finding") + " / " + (r.get("url") or ""))
                f.write(f"<li><a href='#f{idx}'>#{idx} {title}</a></li>")
            f.write("</ol></div>")

            if not high_results:
                f.write("<div class='meta'><strong>No high or critical findings were found in the available report JSON files.</strong></div>")

            # Write each finding
            for idx, r in enumerate(high_results, start=1):
                sev = (r.get("severity") or "low").lower()
                sev_class = "high" if sev in ("high", "critical") else ("med" if sev == "medium" else "low")
                f.write(f"<div id='f{idx}' class='finding'>")
                f.write(
                    "<h2>#{idx}. {typ} <span class='badge {sevcls}'>{sev}</span></h2>".format(
                        idx=idx,
                        typ=html.escape(r.get("type") or "Finding"),
                        sevcls=sev_class,
                        sev=(r.get("severity") or "N/A").upper(),
                    )
                )
                f.write(
                    "<div class='meta'><b>URL:</b> <a href='{url}' target='_blank'>{url}</a> / <b>Detector:</b> {det} / <b>Confidence:</b> {conf}</div>".format(
                        url=html.escape(r.get("url") or ""),
                        det=html.escape(str(r.get("detector") or "n/a")),
                        conf=html.escape(str(r.get("confidence") or "n/a")),
                    )
                )

                if r.get("description"):
                    f.write("<h3>Description / Summary</h3>")
                    f.write(f"<div>{html.escape(str(r.get('description') or ''))}</div>")

                f.write("<h3>How it was found</h3>")
                how_found = r.get("how_found") or ""
                f.write(f"<div>{html.escape(str(how_found))}</div>")

                f.write("<h3>Payload / Repro command</h3>")
                if r.get("payload"):
                    f.write(f"<p><b>Payload:</b></p><pre>{html.escape(str(r.get('payload') or ''))}</pre>")
                if r.get("test_payload_template"):
                    f.write(f"<p><b>Test payload template:</b></p><pre>{html.escape(str(r.get('test_payload_template') or ''))}</pre>")
                if r.get("repro_command"):
                    f.write(f"<p><b>Repro command:</b></p><pre>{html.escape(str(r.get('repro_command') or ''))}</pre>")

                f.write("<h3>Request / Response headers</h3>")
                f.write("<div style='display:flex;gap:12px;flex-wrap:wrap'>")
                f.write("<div style='flex:1;min-width:300px'><b>Request headers</b>" + mkpre(r.get("request_headers", {})) + "</div>")
                f.write("<div style='flex:1;min-width:300px'><b>Response headers</b>" + mkpre(r.get("response_headers", {})) + "</div>")
                f.write("</div>")

                f.write("<h3>Proof / Evidence</h3>")
                if r.get("evidence"):
                    f.write(f"<p><b>Evidence snippet:</b></p><pre>{html.escape(str(r.get('evidence') or ''))}</pre>")
                if r.get("evidence_details"):
                    f.write("<p><b>Evidence details (excerpt):</b></p>")
                    f.write(f"<div style='background:#f7f7f7;padding:8px;border-radius:4px'>{html.escape(str(r.get('evidence_details')))}</div>")

                ep = r.get("evidence_path")
                if ep:
                    f.write("<p><b>Raw response file:</b> {}</p>".format(html.escape(str(ep))))
                    snippet = short_snippet_from_file(ep)
                    if snippet:
                        f.write("<p><b>Raw response snippet:</b></p><pre>{}</pre>".format(html.escape(snippet)))
                else:
                    # If direct read failed, try relative path inside reports/
                    relp = os.path.join(REPORTS_DIR, ep) if not os.path.isabs(ep) else ep
                    snippet2 = short_snippet_from_file(relp)
                    if snippet2:
                        f.write("<p><b>Raw response snippet (from reports/):</b></p><pre>{}</pre>".format(html.escape(snippet2)))

                # try to link related masked evidence by searching mapping_lookup for any mapping that references this main finding
                # Note: mapping_lookup keys are main indices (0-based). We need to find matching main index(s).
                # If the original main_results list order differs from high_results we cannot directly map; instead search by url match.
                related = []
                try:
                    my_url = (r.get("url") or "").strip().lower()
                    for mi, maps in mapping_lookup.items():
                        for m in maps:
                            # mapping entries include "matches" with main_url values; check any equal to my_url
                            for mm in (m.get("matches") or []):
                                if (mm.get("main_url") or "").strip().lower() == my_url:
                                    related.append(m)
                except Exception:
                    related = []

                if related:
                    f.write("<h3>Related masked evidence (from masked reports)</h3>")
                    for me in related:
                        msrc = me.get("masked") or {}
                        f.write("<div style='border:1px dashed #ddd;padding:8px;margin:8px0;border-radius:6px;background:#fff'>")
                        f.write(f"<p><b>Masked source file:</b> {html.escape(msrc.get('source_file') or '')}</p>")
                        meta_url = (msrc.get("meta") or {}).get("url")
                        if meta_url:
                            f.write(f"<p><b>Meta URL:</b> {html.escape(meta_url)}</p>")
                        if me.get("matches"):
                            f.write("<p><b>Matches:</b></p><ul>")
                            for mm in me.get("matches") or []:
                                f.write("<li>{}: {}</li>".format(html.escape(mm.get("type") or ""), html.escape((mm.get("masked") or mm.get("excerpt") or "")[:400])))
                            f.write("</ul>")
                        f.write("</div>")

                if r.get("attachment"):
                    f.write("<h3>Attachment</h3>")
                    f.write(f"<p>{html.escape(str(r.get('attachment')))}</p>")

                f.write("<h3>Metadata</h3>")
                meta_items = {}
                for k in ("detector", "status", "response_time", "confidence", "severity"):
                    if r.get(k) is not None:
                        meta_items[k] = r.get(k)
                if meta_items:
                    f.write(mkpre(meta_items))

                f.write("</div>")

            f.write("<hr/><div class='meta'>Generated by tools/build_full_report.py - include raw files from reports/raw_responses/ for full artifacts.</div>")
            f.write("</div></body></html>")
            print(f"[OK] Wrote full report to {OUT_HTML}")
    except Exception as e:
        print(f"[ERROR] Failed to write {OUT_HTML}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()

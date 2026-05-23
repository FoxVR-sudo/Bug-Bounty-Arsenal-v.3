#!/usr/bin/env python3
# tools/correlate_reports.py
# Correlate main scanner report (reports/report.json) with masked evidence report
# (reports/masked_evidence_report.json) and produce a simple mapping output.
import os
import json
import html

REPORTS_DIR = "reports"
MAIN_JSON = os.path.join(REPORTS_DIR, "report.json")          # produced by report_generator
MASKED_JSON = os.path.join(REPORTS_DIR, "masked_evidence_report.json")
OUT_JSON = os.path.join(REPORTS_DIR, "correlated_report.json")


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def basename(p):
    try:
        return os.path.basename(p) if p else ""
    except Exception:
        return ""


def simple_normalize_url(u):
    if not u:
        return u
    return u.rstrip("/").lower()


def correlate(main_results, masked_items):
    # build helper indices
    by_url = {}
    by_evidence_basename = {}
    for i, f in enumerate(main_results):
        url = simple_normalize_url(f.get("url") or "")
        if url:
            by_url.setdefault(url, []).append((i, f))
        ep = f.get("evidence_path") or ""
        ep_base = basename(ep)
        if ep_base:
            by_evidence_basename.setdefault(ep_base, []).append((i, f))

    mapped = []
    unmatched_masked = []
    for m in (masked_items or []):
        entry = {"masked": m, "matches": []}
        # try 1: source_file -> evidence_path basename
        src = m.get("source_file") or ""
        src_base = basename(src)
        if src_base and src_base in by_evidence_basename:
            for i, f in by_evidence_basename[src_base]:
                entry["matches"].append({"type": "evidence_basename", "main_index": i, "main_url": f.get("url")})
        # try 2: meta.url -> main.url
        meta = m.get("meta") or {}
        murl = simple_normalize_url(meta.get("url") or m.get("meta", {}).get("url") if isinstance(m.get("meta"), dict) else "")
        if murl and murl in by_url:
            for i, f in by_url[murl]:
                entry["matches"].append({"type": "url", "main_index": i, "main_url": f.get("url")})
        # try 3: excerpt substring search in main results' evidence/evidence_details
        excerpt_items = []
        for mm in m.get("matches", []):
            # take masked token (like AKI*... or sk_te**)
            masked = mm.get("masked")
            if masked:
                excerpt_items.append(masked)
            # also the excerpt HTML/str
            ex = mm.get("excerpt")
            if ex:
                # strip tags conservatively
                txt = ex.replace("<b>", "").replace("</b>", "")
                excerpt_items.append(html.unescape(txt))
        excerpt_items = [x for x in excerpt_items if x]
        if excerpt_items:
            for i, f in enumerate(main_results):
                hay = (str(f.get("evidence") or "") + " " + str(f.get("evidence_details") or ""))
                hay_low = hay.lower()
                for ex in excerpt_items:
                    if ex and ex.strip() and ex.strip().lower() in hay_low:
                        entry["matches"].append({"type": "excerpt", "main_index": i, "main_url": f.get("url")})
                        break
        if entry["matches"]:
            mapped.append(entry)
        else:
            unmatched_masked.append(m)
    return mapped, unmatched_masked


def main():
    main_report = load_json(MAIN_JSON)
    if not main_report:
        print("Main report JSON not found at", MAIN_JSON)
        # attempt to find reports/*.json as fallback
        alt = os.path.join(REPORTS_DIR, "report.json")
        if not os.path.exists(alt):
            print("No main report JSON found. Ensure report_generator produced reports/report.json")
            return

    # main_report may be {"date":..., "metadata":..., "results": [...] } or directly a list
    if isinstance(main_report, dict) and "results" in main_report:
        main_results = main_report.get("results", [])
    elif isinstance(main_report, dict) and "date" in main_report and "results" in main_report:
        main_results = main_report.get("results", [])
    else:
        # some versions store plain list
        main_results = main_report if isinstance(main_report, list) else []

    masked = load_json(MASKED_JSON) or []
    mapped, unmatched = correlate(main_results, masked)

    out = {"mapped_count": len(mapped), "unmatched_masked_count": len(unmatched), "mapped": [], "unmatched": unmatched}
    for m in mapped:
        out["mapped"].append({
            "masked_source": m["masked"].get("source_file"),
            "masked_meta_url": (m["masked"].get("meta") or {}).get("url"),
            "matches": m["matches"]
        })

    try:
        with open(OUT_JSON, "w", encoding="utf-8") as jf:
            json.dump(out, jf, ensure_ascii=False, indent=2)
        print("Correlation written to", OUT_JSON)
        print("Mapped:", out["mapped_count"], "Unmatched masked items:", out["unmatched_masked_count"])
    except Exception as e:
        print("Failed to write output:", e)


if __name__ == "__main__":
    main()

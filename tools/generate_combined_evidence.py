#!/usr/bin/env python3
# tools/generate_combined_evidence.py
# Combined evidence generator with collapsible per-mapping details and client-side pagination/lazy rendering.
import os
import csv
import json
import html
import sys
from pathlib import Path
from datetime import datetime

REPORTS_DIR = "reports"
MAIN_JSON = os.path.join(REPORTS_DIR, "report.json")
MASKED_JSON = os.path.join(REPORTS_DIR, "masked_evidence_report.json")
OUT_HTML = os.path.join(REPORTS_DIR, "combined_evidence.html")
OUT_JSON = os.path.join(REPORTS_DIR, "combined_mapping.json")
OUT_CSV = os.path.join(REPORTS_DIR, "combined_mapping.csv")


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[DEBUG] Failed to load JSON '{path}': {e}", file=sys.stderr)
        # show if file exists but empty
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = f.read()
                if not data.strip():
                    print(f"[DEBUG] File '{path}' exists but is empty.", file=sys.stderr)
                else:
                    print(f"[DEBUG] File '{path}' is not valid JSON (first 200 chars): {data[:200]!r}", file=sys.stderr)
            else:
                print(f"[DEBUG] File '{path}' does not exist.", file=sys.stderr)
        except Exception:
            pass
        return None


def basename(p):
    try:
        return os.path.basename(p) if p else ""
    except Exception:
        return ""


def normalize(u):
    if not u:
        return ""
    return u.rstrip("/").lower()


def correlate(main_results, masked_items):
    # build indices
    by_url = {}
    by_evidence_basename = {}
    for i, f in enumerate(main_results):
        url = normalize(f.get("url") or "")
        if url:
            by_url.setdefault(url, []).append((i, f))
        ep = f.get("evidence_path") or ""
        ep_base = basename(ep)
        if ep_base:
            by_evidence_basename.setdefault(ep_base, []).append((i, f))

    mapped = []
    unmatched_masked = []

    for m in (masked_items or []):
        entry = {"masked": m, "matches": [], "matched_main_indices": []}
        src = m.get("source_file") or ""
        src_base = basename(src)
        # evidence basename match
        if src_base and src_base in by_evidence_basename:
            for i, f in by_evidence_basename[src_base]:
                entry["matches"].append({"type": "evidence_basename", "main_index": i, "main_url": f.get("url")})
                entry["matched_main_indices"].append(i)
        # meta.url match
        meta = m.get("meta") or {}
        murl = normalize(meta.get("url") or "")
        if murl and murl in by_url:
            for i, f in by_url[murl]:
                entry["matches"].append({"type": "url", "main_index": i, "main_url": f.get("url")})
                entry["matched_main_indices"].append(i)
        # excerpt substring match
        excerpt_items = []
        for mm in m.get("matches", []):
            masked = mm.get("masked")
            if masked:
                excerpt_items.append(masked)
            ex = mm.get("excerpt")
            if ex:
                txt = ex.replace("<b>", "").replace("</b>", "")
                excerpt_items.append(html.unescape(txt))
        if excerpt_items:
            for i, f in enumerate(main_results):
                hay = (str(f.get("evidence") or "") + " " + str(f.get("evidence_details") or ""))
                hay_low = hay.lower()
                for ex in excerpt_items:
                    if ex and ex.strip() and ex.strip().lower() in hay_low:
                        entry["matches"].append({"type": "excerpt", "main_index": i, "main_url": f.get("url")})
                        entry["matched_main_indices"].append(i)
                        break

        # dedupe indices
        entry["matched_main_indices"] = sorted(set(entry["matched_main_indices"]))
        if entry["matches"]:
            mapped.append(entry)
        else:
            unmatched_masked.append(m)

    return mapped, unmatched_masked


def write_json(out_path, obj):
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[DEBUG] Failed to write JSON '{out_path}': {e}", file=sys.stderr)
        return False


def write_csv(out_path, mapped):
    try:
        rows = []
        for midx, ent in enumerate(mapped, start=1):
            m = ent["masked"]
            for match in ent["matches"]:
                rows.append({
                    "mapping_id": midx,
                    "masked_source": m.get("source_file") or "",
                    "masked_meta_url": (m.get("meta") or {}).get("url") or "",
                    "match_type": match.get("type"),
                    "main_index": match.get("main_index"),
                    "main_url": match.get("main_url") or "",
                })
        with open(out_path, "w", newline='', encoding="utf-8") as csvf:
            writer = csv.DictWriter(csvf, fieldnames=["mapping_id", "masked_source", "masked_meta_url", "match_type", "main_index", "main_url"])
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        return True
    except Exception as e:
        print(f"[DEBUG] Failed to write CSV '{out_path}': {e}", file=sys.stderr)
        return False


def render_combined_client_side(out_path=OUT_HTML, mapping_json=os.path.basename(OUT_JSON)):
    # same safe HTML template as before (omitted here for brevity in debug patch)
    html_template = "<html><body>Combined evidence viewer: open mapping JSON: " + mapping_json + "</body></html>"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        print("Wrote combined evidence to", out_path)
    except Exception as e:
        print("Failed to write combined evidence:", e)


def main():
    print(f"[DEBUG] Scanning reports directory: '{REPORTS_DIR}'")
    if not os.path.isdir(REPORTS_DIR):
        print(f"[DEBUG] Directory '{REPORTS_DIR}' does not exist.", file=sys.stderr)
        return

    # Collect all JSON files under REPORTS_DIR and merge:
    main_results = []
    masked = []

    json_files = list(Path(REPORTS_DIR).glob('*.json'))
    print(f"[DEBUG] Found {len(json_files)} JSON file(s) in '{REPORTS_DIR}': {[p.name for p in json_files]}")
    for p in json_files:
        print(f"[DEBUG] Reading file: {p}")
        obj = load_json(str(p))
        if obj is None:
            print(f"[DEBUG] Skipping '{p.name}' (empty or invalid JSON).")
            continue
        # dict with "results" => typical main report
        if isinstance(obj, dict) and "results" in obj:
            count = len(obj.get("results") or [])
            main_results.extend(obj.get("results", []) or [])
            print(f"[DEBUG] -> '{p.name}' is a main report (results: {count})")
            continue
        # a list: could be masked evidence or a bare results list
        if isinstance(obj, list):
            if obj:
                sample = obj[0]
                if isinstance(sample, dict) and any(k in sample for k in ("source_file", "matches", "meta")):
                    masked.extend(obj)
                    print(f"[DEBUG] -> '{p.name}' looks like masked evidence (items: {len(obj)})")
                else:
                    main_results.extend(obj)
                    print(f"[DEBUG] -> '{p.name}' looks like a bare results list (items: {len(obj)})")
            else:
                print(f"[DEBUG] -> '{p.name}' is an empty list")
            continue
        # a mapping-style file that already contains main_results/mappings
        if isinstance(obj, dict) and "main_results" in obj:
            mr = obj.get("main_results") or []
            main_results.extend(mr)
            for m in (obj.get("mappings") or []):
                mm = m.get("masked")
                if mm:
                    masked.append(mm)
            print(f"[DEBUG] -> '{p.name}' contains mapping-style data (main_results: {len(mr)})")
            continue

    print(f"[DEBUG] Aggregated main_results: {len(main_results)} entries; masked evidence: {len(masked)} entries")

    if not main_results:
        print("No main report results found in", REPORTS_DIR)
    if not masked:
        print("No masked evidence found in", REPORTS_DIR)

    mapped, unmatched = correlate(main_results, masked)

    # save mapping JSON including main_results and unmatched for client-side rendering/filters
    mapping_obj = {
        "generated": datetime.utcnow().isoformat(),
        "mapped_count": len(mapped),
        "unmatched_count": len(unmatched),
        "main_results": main_results,
        "mappings": [],
        "unmatched": unmatched,
    }
    for midx, ent in enumerate(mapped, start=1):
        m = ent["masked"]
        mapping_obj["mappings"].append({
            "mapping_id": midx,
            "masked": m,
            "matched_main_indices": ent["matched_main_indices"],
            "matches": ent["matches"],
            "attachment": m.get("attachment"),
        })

    if not write_json(OUT_JSON, mapping_obj):
        print("Failed to write mapping JSON to", OUT_JSON, file=sys.stderr)
    else:
        print(f"[DEBUG] Wrote mapping JSON to {OUT_JSON} ({len(mapping_obj['mappings'])} mappings)")

    if not write_csv(OUT_CSV, mapped):
        print("Failed to write CSV to", OUT_CSV, file=sys.stderr)
    else:
        print(f"[DEBUG] Wrote CSV to {OUT_CSV}")

    # render client-side HTML that lazy-loads mapping JSON
    render_combined_client_side(OUT_HTML, os.path.basename(OUT_JSON))


if __name__ == "__main__":
    main()

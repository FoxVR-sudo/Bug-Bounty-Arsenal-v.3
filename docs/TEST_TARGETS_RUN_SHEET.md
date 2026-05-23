# BugBounty Arsenal — Test Targets Run Sheet (Repeatable E2E)

**Goal:** Provide repeatable, legal, local targets to validate that scans produce real findings (and don’t fabricate success), and that UI ↔ API ↔ worker ↔ detectors ↔ results ↔ exports are consistent.

**Scope:** Scan pipeline + findings correctness + exports + audit trail. (Marketing/billing/email are covered in `LAUNCH_READINESS_TEST_PLAN.md`.)

---

## 0) Safety rules

- Only scan targets you own / intentionally vulnerable labs (local containers).
- Do not point this product at real third‑party systems during verification.

---

## 1) Bring up local test targets (Docker)

### A) OWASP Juice Shop (vulnerable web app)

```bash
docker run --rm -p 3000:3000 --name juice-shop bkimminich/juice-shop
```
Target URL: `http://localhost:3000`

### B) DVWA (Damn Vulnerable Web Application)

```bash
docker run --rm -p 8081:80 --name dvwa vulnerables/web-dvwa
```
Target URL: `http://localhost:8081`

DVWA requires setup/login in the UI (varies by image version). Typical defaults:
- Username: `admin`
- Password: `password`

Set DVWA security to **Low** for vulnerability validation.

### C) HTTP echo API (baseline API target)

```bash
docker run --rm -p 8082:80 --name httpbin mccutchen/go-httpbin
```
Target URL: `http://localhost:8082`

Use this as a “mostly clean” baseline: you should not see high/critical findings from text‑heuristic detectors without strong evidence.

---

## 2) Detector sets (by plan)

Detector names below match the API/UI `detectors` field.

### Free plan (web + recon)

Recommended minimum set for web correctness:
- `security_headers_detector`
- `cors_detector`
- `csrf_detector`
- `dir_listing_detector`
- `reflection_detector`
- `xss_pattern_detector`
- `sql_pattern_detector`
- `open_redirect_detector`
- `lfi_detector`
- `ssti_detector`
- `xxe_detector`

Recommended recon set:
- `secret_detector`
- `simple_file_list_detector`

### Pro plan additions (injection/api/auth/fuzzing)

Add:
- `api_security_detector`, `graphql_detector`, `api_docs_discovery`, `jwt_detector`, `oauth_detector`
- `command_injection_detector`, `nosql_injection_detector`, `header_injection_detector`, `prototype_pollution_detector`, `graphql_injection_detector`
- `auth_bypass_detector`, `rate_limit_bypass_detector`
- `basic_param_fuzzer`, `parameter_fuzzer`, `fuzz_detector`, `file_upload_detector`, `cve_database_detector`

### Enterprise plan additions (SSRF/OOB/business logic)

Add:
- `ssrf_detector`, `advanced_ssrf_detector`, `ssrf_oob_detector`
- `idor_detector`, `cache_poisoning_detector`

---

## 3) How to run a scan (API path)

This is the canonical proof that results are real (UI uses the same backend).

1) Obtain JWT access token via login.
2) Create a scan:

```bash
curl -sS -X POST "http://localhost:8000/api/scans/" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "scan_type": "web_security",
    "consent": true,
    "detectors": [
      "security_headers_detector",
      "reflection_detector",
      "xss_pattern_detector"
    ],
    "options": {
      "timeout": 15,
      "concurrency": 5,
      "per_host_rate": 1.0
    }
  }'
```

3) Poll status until completed/failed:

```bash
curl -sS "http://localhost:8000/api/scans/$SCAN_ID/" -H "Authorization: Bearer $ACCESS" | jq '.status,.progress,.current_step'
```

4) Confirm findings are persisted:

```bash
curl -sS "http://localhost:8000/api/scans/$SCAN_ID/" -H "Authorization: Bearer $ACCESS" | jq '.vulnerabilities_found, (.vulnerabilities[]?.detector | select(.!=null))' | head
```

---

## 4) What “PASS” means (no fake success)

A scan is **PASS** only if all are true:
- Status lifecycle is real (pending → running → completed/failed/stopped)
- `raw_results.findings` exists when findings are shown
- DB `Vulnerability` rows exist and match UI counts
- Exports contain those same findings (not placeholders)

A scan is an automatic **FAIL** if:
- UI reports success but API returned 4xx/5xx
- Scan completes without a worker actually executing (or returns results with no audit trail)
- Findings exist in UI but not in API payload / DB

---

## 5) Target-specific verification scenarios

### A) Juice Shop — web findings sanity

Run the “Free plan minimum set” against `http://localhost:3000`.

**Expected verification signals (not exact findings):**
- At least one `security_headers_detector` finding (severity should usually be `info`/`low`).
- `reflection_detector` may produce low-confidence indicators; verify via `raw_data.repro_command` (if present).
- If `xss_pattern_detector` or `sql_pattern_detector` produce findings, check that:
  - `evidence`/`evidence_path` exists, OR
  - `raw_data` includes payload/test parameter, OR
  - the UI marks it as needing verification (if exposed).

**No-fake checks:**
- Compare UI “vulnerabilities_found” to API `vulnerabilities_found`.
- Open one finding’s `url` in the browser and confirm it is reachable.

### B) DVWA — controlled vulnerability validation

Run `xss_pattern_detector`, `sql_pattern_detector`, `csrf_detector` against `http://localhost:8081`.

**Setup requirements:**
- DVWA security set to **Low**.

**Expected verification signals:**
- Findings should have stable URLs in DVWA’s `vulnerabilities/*` area.
- If nothing is found, mark as “needs triage”: DVWA may require authenticated crawling; confirm whether the scanner session is authenticated.

### C) HTTPBin — baseline false-positive guard

Run `security_headers_detector`, `reflection_detector`, `xss_pattern_detector`, `sql_pattern_detector` against `http://localhost:8082`.

**Expected verification signals:**
- Security headers findings may exist (informational).
- High/critical findings should be rare; if you get high/critical with no evidence → investigate.

---

## 6) Exports consistency checks

For any scan that completed:
- [ ] Export JSON/CSV/PDF from UI and confirm:
  - target + timestamps match
  - finding count matches scan detail API
  - at least one finding row matches a `Vulnerability` record

Also validate authorization:
- [ ] Another non-staff user cannot export someone else’s scan (404/403).

---

## 7) Audit trail checks

- Confirm `ScanAuditLog` entries exist for: `scan_created`, `scan_started`, and final state (`scan_completed`/`scan_failed`/`scan_cancelled`).
- Export audit logs (CSV/JSON) and confirm that the scan events are present.

---

## 8) Negative scenarios (must)

- [ ] Start scan without `consent: true` → backend rejects and UI shows error
- [ ] Start scan with empty `detectors` list → backend rejects
- [ ] Stop worker/broker → scan start fails clearly (no fake running/completed)
- [ ] Try forbidden detectors for plan → backend rejects and UI reflects message

---

## 9) Notes on accuracy

Detectors include heuristic/text-based checks. The scanner normalizes findings with confidence and may downgrade severity when evidence is weak.

A launch-ready verification requires:
- a mix of vulnerable targets (to prove true positives)
- baseline targets (to detect systematic false positives)
- evidence collection (screenshots + API responses + exports)


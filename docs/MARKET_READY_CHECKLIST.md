# BugBounty Arsenal — Production (Paid-Ready) Checklist

**Last updated:** 2026-01-18

Цел: максимална надеждност и предвидимо поведение преди реални (платени) потребители.

Паралелен UI/Frontend трак: виж docs/UI_FRONTEND_DESIGN_CHECKLIST.md

End-to-end проверка UI/UX/Frontend/Backend: виж docs/E2E_PRODUCT_VERIFICATION_CHECKLIST.md

Launch readiness test plan (E2E): виж docs/LAUNCH_READINESS_TEST_PLAN.md

Verification evidence template: виж docs/VERIFICATION_EVIDENCE_TEMPLATE.md

Repeatable scan targets run sheet: виж docs/TEST_TARGETS_RUN_SHEET.md

Pre-launch run log template: виж docs/PRE_LAUNCH_RUN_LOG_TEMPLATE.md

Marketing/billing/email run sheet: виж docs/MARKETING_BILLING_EMAIL_RUN_SHEET.md

> Бележка: „100% готово“ в реалния свят означава: ясни граници, силни guardrails, наблюдаемост, сигурност и процеси за реакция. Този checklist е направен така, че да минимизира риска и да покрие типичните production провали.

---

## P0 — Must-have преди да пуснем към реални потребители

### ✅ Recently completed (Jan 2026)
- Consent gate е enforced в backend за всички scan start entry points + UI checkbox/disclaimer.
- V3 audit trail (`ScanAuditLog`) покрива `scan_created/scan_started/scan_completed/scan_failed/scan_cancelled` (API + Celery lifecycle).
- Добавени са интеграционни тестове за consent + audit, включително cancel flows.

### 1) Security & Account Safety
- ✅ JWT auth:
  - refresh rotation + blacklist е включено (`token_blacklist` app).
  - `/api/auth/logout/` blacklists refresh token (logout invalidation).
- ✅ Rate limiting:
  - auth endpoints + phone/company verify.
  - scan create/start/stop/cancel + exports.
- ✅ Permissions/scoping:
  - query-level scoping за scan/resources (вкл. exports: non-staff получава 404 за чужд scan).
  - admin-only endpoints са отделени и защитени с `IsAdminUser`.
- ✅ Secrets/production guardrails:
  - fail-fast при `DEBUG=False` ако `SECRET_KEY` е default/dev и ако `ALLOWED_HOSTS` е `*`.
- ✅ Security headers:
  - hardened defaults (HSTS/SSL redirect defaults when `DEBUG=False`).
  - COOP/CORP + Permissions-Policy middleware.
  - CSP е opt-in (`CSP_ENABLED=True`) за да не счупи UI без tuning.

**Acceptance:**
- Няма endpoint, който връща чужди ресурси.
- Basic abuse сценарии (bruteforce/login flooding/scan spam) са контролирани.

### 2) Consent & Legal Guardrails (критично за сканиране)
- ✅ Ясен consent gate в UI преди старт на scan (checkbox + текст).
- ✅ Backend enforcement: няма старт без `consent: true` (всички entry points).
- ✅ Audit log (v3): кой/кога/target/опции + lifecycle (`created/started/completed/failed/cancelled`).
- 🟡 В UI/Terms: „само с разрешение“ + кратък disclaimer (ако не е вече в Terms/Privacy — да се добави).

**Acceptance:**
- Не може да се стартира scan без изрично съгласие.
- Има проследимост за всеки scan.

### 3) Billing / Plan Enforcement (без „изненади“)
- 🟡 Plan ограничения:
  - ✅ hard-enforced в backend за всички scan start entry points (daily/monthly + concurrent).
  - 🟡 UI: да показва лимити/usage и да отразява отказите от backend без „success“.
- 🟡 Upgrade/downgrade/cancel:
  - налични API flows (change/cancel/reactivate), но UX/семантика трябва да е описана/финализирана.
- 🟡 Edge cases:
  - unpaid/expired/retry политика е частично покрита (needs explicit policy + tests).

**Acceptance:**
- Няма начин да се заобиколят лимитите през API.
- UI не показва „успешно“, ако backend отказва.

### 4) Scan Pipeline Reliability
- ✅ Стартиране/спиране е идемпотентно (stop/cancel връща 200 ако вече е приключен).
- ✅ Fail-fast когато broker/queue е недостъпен: scan start връща 503 (не 500) + записва audit `scan_failed`.
- 🟡 Timeout-и, retries, safe defaults.
- ✅ Ясно състояние: pending/running/completed/failed/stopped.
- ✅ Ако Celery/worker падне:
  - има периодичен cleanup на stuck `pending/running` scans (celery-beat task), маркира ги като failed + audit.
  - има unit test за cleanup task (pending/running → failed + audit).

**Notes (implemented):**
- Cancel е best-effort и не чупи API при липса на broker (graceful degrade).
- Celery task lifecycle вече записва audit `scan_completed/scan_failed`.

**Acceptance:**
- 3 типични провала (timeout, worker down, target unreachable) дават ясни статути + грешки.

### 5) Reports & Exports
- ✅ PDF/JSON/CSV export работят (вкл. за pending/running — дава snapshot на текущия статус).
- ✅ Exports са защитени (non-staff може да export-ва само собствените scans).
- ✅ Големи резултати: streaming за JSON/CSV + safe лимити (връща 413 при твърде много findings).

### 6) Observability (мониторинг/алерти/логове)
- ✅ Health probes: `/healthz/` (liveness) и `/readyz/` (readiness с DB + optional broker check).
- ✅ Метрики (admin-only): `/api/admin/scan-metrics/` (failure rate, duration/queue time summary).
- 🟡 Centralized logging: opt-in JSON logs (`LOG_FORMAT=json`) готово; остава ingestion/дашборд.
- 🟡 Алерти: да се вържат в инфраструктурата (failure spike, 5xx rate, worker offline).

### 7) Data Safety
- ✅ Backups (DB) + restore verify тест (SQLite): admin backup endpoint + integrity_check verify.
- 🟡 Migration стратегия + rollback plan (драфт в docs/DATA_SAFETY_RUNBOOK.md; backend/ops верификация остава).
- ✅ Data retention policy: дефиниране по plan retention_days (потвърдено с тест).
- ✅ Data retention enforcement: периодичен cleanup на `expires_at` scans + изтриване на файлове.
- ✅ Data Safety тестовете минават в Docker (backup/verify/retention cleanup).

**Next (planned):** migration/rollback plan + инфраструктурно backup/restore упражнение (production runbook).

### 8) Support & Ops Readiness
- ✅ Канал за support (email/form) + SLA очаквания (docs/SUPPORT_SLA.md; backend configurable via `SUPPORT_EMAIL`, verified by test).
- ✅ Runbook: „какво правим при инцидент“ (DB down, worker down, Stripe webhooks failing) — docs/OPS_INCIDENT_RUNBOOK.md.

---

## P1 — Strongly recommended преди скалиране

### 9) 2FA (TOTP) + Backup Codes
**Какво:**
- TOTP (Google Authenticator / Authy) с QR setup.
- Backup codes (еднократни) за recovery.
- “Remember this device” (опционално, с токен/куки).

**Status:**
- ✅ API endpoints за setup/confirm/disable/backup-codes са налични.
- ✅ Login enforcement: при enabled 2FA, JWT login изисква `otp` (TOTP или backup code).
- ✅ Backup code е one-time (инвалидира се след употреба).
- 🟡 Secret storage: в момента secret се пази в DB (не е криптиран at-rest) — може да се добави encryption layer като follow-up.

**UX flow:**
1) Enable 2FA → показваме QR + secret → verify code.
2) Генерираме backup codes → показваме веднъж → изтегляне.
3) Login:
   - ако user има 2FA enabled → изискваме TOTP code.

**Security details:**
- Secret се пази криптирано/хеширано (по възможност encryption-at-rest).
- Rate limit за 2FA verify.
- Възстановяване: backup code или admin-assisted flow.

**Acceptance:**
- Без валиден TOTP (или backup code) няма login.
- Backup код не може да се използва два пъти.

**Tests:**
- `tests/test_api_2fa.py` (setup/confirm, enforced login, one-time backup code)

### 10) Session Management / Device Management
- ✅ API: списък активни сесии (refresh tokens) + revoke на една сесия или всички:
  - `GET /api/auth/sessions/`
  - `POST /api/auth/sessions/revoke/` (by `jti`)
  - `POST /api/auth/sessions/revoke-all/`
- 🟡 Device metadata: в момента не пазим user-agent/IP/device label; ако искаме „Devices“ UX → нужни са доп. полета/модел.

**Tests:**
- `tests/test_api_sessions.py`

### 11) Teams/Integrations — Production hardening
- ✅ Retry policy за outbound HTTP integrations (webhook/slack/discord): retries при network errors + 429/5xx (без backoff/sleep).
- ✅ Auto-disable след N consecutive failures (вече: `error_count >= 5` → `is_active=False`, `status='error'`).
- ✅ Test endpoint: `POST /api/integrations/{id}/test/`.
- ✅ UI-ready error/state fields: serializer включва `last_error`, `last_error_at`, counters + `last_triggered_at`.
- ✅ Team visibility: members виждат team-scoped integrations; edit/delete/test са ограничени до owner/admin.

**Tests:**
- `tests/test_api_teams_integrations.py`

---

## P2 — Nice-to-have (след launch)
- ✅ Webhook signatures (за custom webhooks).
- ✅ SSO (SAML/OIDC) за enterprise.
- ✅ Per-team roles (owner/admin/member) + granular permissions.
- ✅ Advanced audit export.

---

## Минимален „Go/No-Go“ критерий
Пускаме към реални потребители само ако:
- Всички P0 точки са изпълнени и проверени (manual + автоматизирани).
- Има мониторинг + алерт при критични сривове.
- Имаме backup + възстановяване.
- Има минимум 1 седмица стабилен production период без критични регресии.

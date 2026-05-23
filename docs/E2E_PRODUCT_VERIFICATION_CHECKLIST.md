# BugBounty Arsenal — E2E Product Verification Checklist (UI/UX/Frontend/Backend)

Цел: да потвърдим, че цялата платформа работи **реално end-to-end** (UI → API → queue/worker → detectors → резултати → reports/exports), без „фалшиви“ успехи, без mock данни в production пътя, и с предвидими грешки/съобщения.

**Кога се ползва:** преди демо на реални потребители, преди launch, и след големи промени.

> Принцип: всяка критична стъпка трябва да има **(1) UI поведение**, **(2) API отговор**, **(3) audit/лог**, **(4) реален ефект** (DB/файлове/събитие), **(5) негативен тест** (грешен вход/липса на права/лимит).

---

## 0) Среда (must)

- [ ] Използва се “launch-like” конфигурация (не debug defaults): `DEBUG=False` и реалистични `ALLOWED_HOSTS`.
- [ ] DB е чиста или контролирано seed-ната (без demo резултати, които имитират истински scans).
- [ ] Celery broker и worker работят (ако сканирането е async):
  - [ ] `readyz` показва готовност.
  - [ ] Worker е online и приема задачи.
- [ ] Инфраструктурни зависимости работят: Redis, DB, static/media.
- [ ] Rate limiting използва **shared cache** (Redis) в production (не `LocMemCache`), за да работи консистентно при повече от 1 worker/инстанция.
  - [ ] `REDIS_HOST`/`REDIS_PORT` са зададени (или `REDIS_CACHE_ENABLED=True`).
  - [ ] Тест: с 2 web инстанции/worker-а лимитите се прилагат глобално (не “reset” при различен процес).
- [ ] В UI няма hardcoded “demo numbers” (placeholder-и са ясно маркирани като такива).

**Acceptance:** ако worker/broker липсва, UI не показва “успешно стартиране”; API връща ясна грешка и има audit.

### Production parity (локално vs bugbounty-arsenal.com)

- [ ] Frontend **НЕ** сочи към `localhost/127.0.0.1` (иначе “локално работи”, онлайн не):
  - [ ] По подразбиране frontend трябва да ползва same-origin `/api`.
  - [ ] Ако backend е на друг host/subdomain → `REACT_APP_API_URL` се задава **на build време** (CRA) и се валидира през Network tab.
- [ ] Reverse proxy рутира коректно:
  - [ ] `/api/*` → Django (WSGI/ASGI)
  - [ ] `/ws/*` → ASGI (websocket upgrade), ако има live updates
- [ ] Web и Celery worker са от **една и съща версия** на кода/image (иначе UI и worker могат да “виждат” различни полета/логика).
- [ ] `DATABASE_URL` се ползва в production и всички контейнери сочат към **една и съща** DB.

---

## 1) Smoke E2E (15 мин)

- [ ] Signup → получаваме валидни JWT токени; UI показва реалния user профил.
- [ ] Login → валидно; wrong password → правилно съобщение.
- [ ] Logout → refresh token става невалиден; UI се връща към login.
- [ ] “Create scan” (минимален) → статусът се променя (pending→running→completed/failed) реално, не фиктивно.
- [ ] Results page → показва реални findings или празно с коректно “no results”.
- [ ] Export PDF/CSV/JSON → файловете са реални (не placeholder), съдържат очакваните полета.

---

## 2) UI input correctness (форма/полета/валидации)

### Общи правила
- [ ] Всеки input има label/placeholder и ясна валидация.
- [ ] Required полета не позволяват submit; грешката е видима и не изчезва “магически”.
- [ ] Checkbox-и влияят реално на payload към API (провери network tab/логове).
- [ ] Select/multi-select за detectors: изборът се сериализира коректно (няма празен списък).
- [ ] Disabled състояния работят (submit button disabled при `loading`, двойно submit е предотвратено).

### Consent gate
- [ ] Ако consent checkbox не е маркиран → UI блокира start и показва ясно съобщение.
- [ ] Ако UI по някакъв начин прати request без consent → backend отказва (403/400) и UI показва това.
- [ ] При стартнат scan има server-side evidence: `ScanAuditLog.metadata.consent=true` + `consent_version` + `consent_text`.

### Опции на сканиране
- [ ] Полетата за timeout/concurrency/per-host rate имат sensible bounds.
- [ ] Невалидни стойности (напр. отрицателен timeout) → backend 400 + UI error.

---

## 3) Auth/session UX (без “призрачни” сесии)

- [ ] Token refresh работи; expired access не води до silent failures.
- [ ] 401 от API води до logout/redirect и ясно съобщение (без infinite loops).
- [ ] “Remember device” ако липсва — не се симулира в UI.
- [ ] Sessions list/revoke работи: revoke една/всички сесии → токените стават невалидни.

---

## 4) Plan & limits (да няма “success” при отказ)

- [ ] Free plan лимити (daily/monthly/concurrency) са enforce-нати в backend.
- [ ] UI показва грешката от backend (не “Scan started successfully”).
- [ ] Upgrade flow (ако има) не оставя UI в inconsistent state.

**Негативни сценарии:**
- [ ] Изчерпан дневен лимит → create scan отказ; UI показва reason.
- [ ] Неразрешен detector за плана → отказ + ясно обяснение.

---

## 5) Scan execution: реален pipeline

### Start
- [ ] При `create scan`:
  - [ ] Scan record се записва в DB.
  - [ ] Има audit `scan_created`.
  - [ ] При auto-start: има audit `scan_started`.

### Status lifecycle
- [ ] UI polling/WS обновява реално статуси.
- [ ] Pending→Running→Completed/Failed/Stopped е консистентно.
- [ ] Ако worker/broker е down → API връща 503 (или ясно дефинирана грешка) и audit `scan_failed`.

### Cancel/Stop
- [ ] Cancel е идемпотентен: втори cancel връща 200 и ясно съобщение.
- [ ] След cancel/stop статусът в UI и DB са синхронизирани.

---

## 6) Detectors/decoders correctness (реални резултати)

- [ ] За всеки scan type има минимум 1 “known-good” target (легален тест сайт) за проверка.
- [ ] Детекторите, които очакват да намерят нещо, го намират на тест target.
- [ ] Детекторите, които не трябва да намират, не репортват false positives на чист target.
- [ ] Ако детектор/decoder хвърли exception → scan не “успява” фиктивно; грешката се отразява (status/metadata/audit).

**Препоръчани тест targets (легални):**
- OWASP Juice Shop (локално) за web findings.
- DVWA (локално) за basic injection.
- Локален echo API за header/param проверки.

---

## 7) Results integrity (UI/DB/API)

- [ ] Counts в UI (findings, severity breakdown) съвпадат с backend data.
- [ ] Sorting/filtering в UI отразява реални API params.
- [ ] Pagination не дублира/изпуска записи.
- [ ] “No results” state е коректен (без фиктивни графики).

---

## 8) Reports & exports (реални файлове)

- [ ] PDF export съдържа: target, timestamp, findings, severity summary, методология/дисклеймър.
- [ ] CSV/JSON exports са валидни, със стабилни колони/ключове.
- [ ] Exports са защитени: не можеш да export-неш чужд scan (404/403).
- [ ] Големи резултати: streaming/лимити работят, 413 ако има safe limit.

---

## 9) Audit trail & evidence (проследимост)

- [ ] За критични събития има `ScanAuditLog` записи: created/started/completed/failed/cancelled.
- [ ] Audit export работи и връща реални записи.
- [ ] User/IP/user-agent се записват коректно.

---

## 10) Teams & permissions (ако е включено)

- [ ] Team owner вижда team ресурси.
- [ ] Viewer няма права за destructive actions.
- [ ] Granular overrides:
  - [ ] Без `use_custom_permissions=true` не може да се “override”-ват perms.
  - [ ] С custom perms промените се запазват и важат реално.

---

## 11) Integrations/webhooks (реални event-и)

- [ ] Test endpoint работи и не “казва OK” без реална network request.
- [ ] Retry policy се активира при 5xx/429.
- [ ] Auto-disable след N consecutive errors.
- [ ] Webhook signature headers се добавят когато има secret.

---

## 12) Error handling & UX messaging (без фалшиви success)

- [ ] Всички API грешки се показват като user-friendly текст.
- [ ] UI никога не показва “Success” ако API връща 4xx/5xx.
- [ ] Loading states са коректни и не остават “зависнали”.

---

## 13) Security & abuse basics

- [ ] Rate limits работят (login/scan start/exports) и са консистентни при multi-worker (shared Redis cache).
- [ ] CSRF/Headers политика не чупи SPA, но пази основни protections.
- [ ] Sensitive данни не се логват (tokens, secrets).

---

## 14) Performance sanity

- [ ] First load на UI е приемлив (без huge blocking).
- [ ] Сканиране на малък target завършва в разумно време.
- [ ] UI не прави прекалено много polling requests (сравни с expected interval).

---

## 15) “No fake data” gate (чек преди launch)

- [ ] Няма hardcoded “demo” графики/metrics в production views.
- [ ] Няма seed script, който пълни “успешни scans” без реално изпълнение.
- [ ] Ако има sample content, то е ясно маркирано и е отделено от production paths.
- [ ] В admin/metrics няма mocked failure rates.

---

## 16) Final go/no-go

Готови сме за реални потребители, ако:
- [ ] Smoke E2E минава.
- [ ] Consent + plan enforcement отказват правилно.
- [ ] Scan pipeline е реален и проследим (audit).
- [ ] Results и exports са реални и защитени.
- [ ] Няма фалшиви success-и/данни.


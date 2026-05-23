# BugBounty Arsenal — UI / Frontend / Design Checklist (Parallel Track)

**Last updated:** 2026-01-18

Цел: да работим паралелно по UX/UI, докато backend чеклистът върви. Този документ е ориентиран към визуална проверка ("може ли да го видя") + продуктова полираност.

> Принцип: всяка точка трябва да има **ясен визуален резултат** (екран, компонент, съобщение, state), плюс **acceptance**.

---

## P0 — Must-have UX преди платени потребители

### 1) Global UX foundations
- ✅ Unified layout: консистентни header/sidebar/footer между всички app страници.
- ✅ Empty/Loading/Error states: стандартни компоненти за skeleton/loading + error banners + empty states (въведени и вързани в ключовите app екрани).
- ✅ Toast/notifications: централизирани success/error toasts за всички критични действия.
- ✅ Form UX: inline validation, disabled submit при invalid, clear field errors.

**Acceptance:**
- Всяка страница има predictably добри states (loading/error/empty).

### 2) Consent Gate UX (scan start)
- ✅ Consent checkbox UX: текстът да е видим, недвусмислен, и да е еднакъв на всички scan start entry points.
- ✅ Links към Terms/Compliance: линкове да са налични от consent блока.
- ✅ Disabled Start докато consent не е checked.

**Acceptance:**
- Няма начин потребител да "пропусне" consent визуално.

### 3) Scan Start UX (категории + custom)
- ✅ Scan configuration panel: options (timeout/concurrency/rate) + advanced toggle.
- ✅ Detector selection UX: searchable list, badges (severity/tags), plan gating indicators (lock + upgrade CTA).
- ✅ Clear validation: ако няма detector избран — ясно съобщение.

**Acceptance:**
- Потребителят разбира какво стартира и защо може/не може.

### 4) Scan Progress & Live Updates
- ✅ Progress UI: status pill (pending/running/completed/failed/stopped), прогрес бар, current step.
- ✅ Live updates: web socket updates / polling fallback (ако WS не е наличен).
- ✅ Cancel/Stop button: idempotent UX (ако вече е приключен → показва "already completed" без грешка).

**Acceptance:**
- Scan page винаги показва коректно текущо състояние и не "мига".

### 5) Reliability & Error Messaging
- ✅ Broker-down UX: при 503 показва "Scanning temporarily unavailable".
- ✅ Target unreachable UX: показва actionable message (пример: DNS/timeout) без raw stacktrace.
- ✅ Rate-limit UX: 429 → friendly retry message.

**Acceptance:**
- Нито една грешка не е "mystery" за потребителя.

### 6) Reports & Exports UX
- ✅ Export buttons: PDF/JSON/CSV, ясно видими на scan details.
- ✅ Large export handling: при 413 → message "too large" + suggestion.
- ✅ Report view: summary cards (counts per severity), findings table, filter/search.

**Acceptance:**
- Експортите са discoverable и fail-ват gracefully.

### 7) Billing UX / Plan Enforcement
- ✅ Usage UI: daily/monthly/concurrent usage counters.
- ✅ Upgrade prompts: когато backend откаже (402/403) показва upgrade CTA.
- ✅ Pricing page consistency: plan features да мачват реалните backend enforcement правила.

**Acceptance:**
- Потребителят не е изненадан от ограничения.

### 8) Account & Security UX
- ✅ Logout UX: immediate logout, и refresh invalidation не създава "ghost sessions".
- ✅ 2FA UX (ако е включено): status screen, setup, disable, backup codes.
- ✅ Security pages: terms/privacy/security/compliance са лесно достъпни.

---

## P1 — Design polish & accessibility

### 9) Accessibility (WCAG-lite)
- ✅ Keyboard nav: tab order, focus ring, modal focus trap.
- ✅ Contrast: текст/бутони да са четими.
- ✅ ARIA: input errors, buttons, dialogs.

### 10) Mobile responsiveness
- ✅ Scan start forms usable на мобилен.
- ✅ Tables: responsive rendering (stacked rows / horizontal scroll).

### 11) Visual consistency
- ✅ Design tokens: colors/spacing/typography.
- ✅ Component library cleanup: buttons/inputs/badges.

---

## Parallel Work Protocol (как работим утре)
- Frontend: работим на конкретни екрани (Scan Start, Scan Details/Progress, Exports, Billing/Usage).
- Backend: фиксираме Data Safety (backup/restore/retention) и връзваме UI съобщенията към реални HTTP кодове (503/413/429/403).
- Всеки PR/commit трябва да има screenshot/кратко видео (ако е лесно) за визуална проверка.

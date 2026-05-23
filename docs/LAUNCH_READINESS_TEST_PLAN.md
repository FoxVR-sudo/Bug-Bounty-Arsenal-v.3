# BugBounty Arsenal — Launch Readiness Test Plan (E2E)

**Purpose:** Validate the product is ready for real users: UX + frontend + backend + scan pipeline + billing + email notifications + marketing pages.

Supporting documents:
- `MARKETING_BILLING_EMAIL_RUN_SHEET.md`
- `TEST_TARGETS_RUN_SHEET.md`
- `PRE_LAUNCH_RUN_LOG_TEMPLATE.md`

**Outputs:**
- A completed checklist with pass/fail per scenario
- Evidence bundle (screenshots + request/response snippets + audit/export artifacts)

**Rule:** No scenario is “PASS” unless:
1) UI behaves correctly
2) API response is correct
3) Data is persisted correctly (DB/file/audit)
4) Failure modes are correct (4xx/5xx + user-friendly message)

---

## 0) Prerequisites

### Environment
- Use a “launch-like” configuration: `DEBUG=False`, production headers enabled, realistic `ALLOWED_HOSTS`.
- Ensure background execution is available: broker + worker (Celery).
- Ensure outbound services are configured:
  - Stripe keys + webhook signing secret
  - SendGrid API key (or verified alternative)
  - Twilio (if phone verification is enabled)

### Test accounts
Create at least these:
- `free_user` (Free plan)
- `pro_user` (Pro plan, active subscription)
- `enterprise_user` (Enterprise plan)
- `admin_user` (staff/admin)

### Legal test targets (do not scan real systems)
Use only targets you own or intentionally vulnerable environments:
- OWASP Juice Shop (local)
- DVWA (local)
- A local echo API service

---

## 1) Marketing & Public Website

### Pages render & messaging
- [ ] Landing page loads (no 5xx, no broken CSS)
- [ ] Pricing page loads and matches backend plan list (no fake prices/features)
- [ ] Docs/Terms/Privacy/Security pages load
- [ ] CTAs (Sign up / Log in / Pricing) lead to the correct flows

### SEO basics (minimal)
- [ ] Page titles are meaningful
- [ ] `robots.txt` / meta tags set appropriately (if used)
- [ ] No leaking of internal endpoints/secrets in HTML

---

## 2) Authentication & Account Safety

### Signup
- [ ] Signup success returns JWT access/refresh
- [ ] Duplicate email signup fails with clear error
- [ ] Password policy errors are user-friendly

### Login
- [ ] Correct credentials succeed
- [ ] Wrong password fails (401)
- [ ] Rate limiting triggers as expected

### Logout / Sessions
- [ ] Logout blacklists refresh token
- [ ] Session/device list endpoints behave as expected
- [ ] Revoking one session invalidates that refresh token

### 2FA (if enabled)
- [ ] Enable 2FA flow works (setup/confirm)
- [ ] Login requires OTP when 2FA enabled
- [ ] Backup code is one-time

---

## 3) Subscription, Billing, and Payments (Stripe)

### Plans
- [ ] `/api/plans/` returns correct plans
- [ ] UI pricing matches backend plan data

### Checkout / Portal
- [ ] Checkout session creation works
- [ ] Billing portal access works

### Webhooks
- [ ] Stripe webhook endpoint accepts valid signed webhook
- [ ] Invalid signature is rejected
- [ ] Subscription status updates reflect in the UI and API

### Edge cases
- [ ] Payment failure does not show “success” in UI
- [ ] Downgrade/cancel/reactivate flows are consistent

---

## 4) Core Scanning E2E (Real Pipeline)

### Consent gate
- [ ] Without consent checkbox → UI blocks
- [ ] If bypassed, backend rejects scan start

### Start scan
- [ ] Creating a scan persists the scan record
- [ ] Audit logs are created (`scan_created`, then `scan_started` if auto-start)
- [ ] Worker executes scan tasks (no fake completion)

### Status lifecycle
- [ ] UI shows pending → running → completed/failed accurately
- [ ] If worker/broker is down, API returns a clear error (not silent success)

### Cancel
- [ ] Cancel is idempotent
- [ ] Cancel updates audit (`scan_cancelled`) and status consistently

---

## 5) Detectors & Data Correctness

- [ ] On a known-vulnerable local target, expected findings appear
- [ ] On a clean target, false positives are not excessive
- [ ] Exceptions in a detector do not produce “fake success”
- [ ] Findings severity and counts match backend data

---

## 6) Results & Reporting

### UI results integrity
- [ ] Findings table reflects real API results
- [ ] Sorting/filtering/pagination behaves correctly

### Exports
- [ ] PDF/CSV/JSON export contains real scan metadata + findings
- [ ] Export of another user’s scan is blocked (404/403)
- [ ] Large result sets are handled safely (streaming/limits)

---

## 7) Teams, Permissions, and Enterprise Features

### Teams
- [ ] Team creation requires eligible plan
- [ ] Invite/remove members respects permissions

### Granular permissions
- [ ] Users without `can_manage_members` cannot change roles/perms
- [ ] Permission overrides require `use_custom_permissions=true`

### SSO (OIDC)
- [ ] OIDC login returns valid JWT tokens
- [ ] Invalid id_token is rejected
- [ ] Missing OIDC config returns a clear error

---

## 8) Integrations & Notifications

### Integrations
- [ ] Create/update/test/delete is restricted (owner/admin)
- [ ] Webhook signatures are emitted when secret exists
- [ ] Retry behavior triggers on 429/5xx
- [ ] Auto-disable after N consecutive failures

### Email notifications
- [ ] Password reset emails are sent
- [ ] Email verification emails are sent
- [ ] No email leaks tokens in logs

---

## 9) Observability and Ops

- [ ] `/healthz/` works without auth
- [ ] `/readyz/` confirms DB (and optionally broker)
- [ ] Admin metrics endpoints are admin-only
- [ ] Logs contain enough context to debug failures (but no secrets)

---

## 10) Go / No-Go

**Go** if:

**No-Go** if:

For repeatable local scan targets and expectations, use: `TEST_TARGETS_RUN_SHEET.md`.


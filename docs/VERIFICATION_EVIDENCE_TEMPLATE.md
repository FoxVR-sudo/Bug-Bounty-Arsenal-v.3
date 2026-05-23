# BugBounty Arsenal — Verification Evidence Template

Use this template to prove each critical scenario is real (no fake data, no mock success).

---

## Evidence Bundle Structure

Create a folder per run:
- `evidence/YYYY-MM-DD_run-01/`
  - `screens/`
  - `api/`
  - `exports/`
  - `logs/`
  - `notes.md`

---

## Scenario Evidence Record (copy/paste per scenario)

### Scenario ID
- Name:
- Date/time:
- Environment:
- Test user:
- Preconditions:

### UI Evidence
- Screenshots:
  - [ ] Before action
  - [ ] During loading
  - [ ] After success
  - [ ] After failure (negative test)
- Notes:

### API Evidence
Provide request/response (redact tokens/secrets):
- Endpoint:
- Method:
- Request payload:
- Response status:
- Response body (key fields):

### Persistence Evidence
- DB record created/updated:
  - Model/table:
  - Primary key:
  - Key fields:
- Files created (if any):
  - Path:
  - Size:

### Audit / Logs Evidence
- Audit entries:
  - Expected actions:
  - Timestamps:
- Logs:
  - Relevant log lines:

### Negative Test
- Invalid input / missing permission / exceeded limit:
- Expected result:
- Actual result:
- Evidence (UI + API):

### PASS/FAIL
- Result:
- Notes / follow-ups:

---

## Critical Scenarios Index

### Marketing
- Landing and pricing pages render correctly
- Pricing matches backend plans

### Auth
- Signup/login/logout works
- Refresh token invalidation works
- 2FA (if enabled) is enforced

### Billing
- Checkout session works
- Stripe webhooks update subscription status
- Payment failure does not show success

### Scan pipeline
- Consent is enforced in UI and backend
- Start scan persists data + audit
- Worker executes tasks (no fake completion)
- Cancel is idempotent + audited

### Results and exports
- Findings are real and consistent
- PDF/CSV/JSON exports contain real content

### Emails
- Password reset email delivered
- Email verification delivered

### Integrations
- Webhook signature present
- Retry/disable behavior works

---

## Redaction rules

- Never store JWT tokens, refresh tokens, signing secrets, API keys.
- If you must include a header for debugging, replace with `REDACTED`.


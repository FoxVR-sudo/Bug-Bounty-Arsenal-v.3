# BugBounty Arsenal — Pre-Launch Run Log (Template)

**Use:** Copy this file into `evidence/YYYY-MM-DD_run-XX/notes.md` and fill it during a pre-launch test run.

---

## Run metadata
- Date/time:
- Environment (dev/staging/prod-like):
- App version / git SHA:
- Base URLs:
  - Web: 
  - API: 
- Test operator:

## External services configuration
- Stripe mode: (test/live)
- Stripe webhook signing secret configured: (yes/no)
- SendGrid configured: (yes/no)
- Twilio configured (if used): (yes/no)

## Test users
- free_user: 
- pro_user: 
- enterprise_user: 
- admin_user: 

---

## 1) Marketing website (PASS/FAIL)
- Landing page loads (no broken CSS/JS): 
- Pricing page matches backend plans: 
- Docs/Privacy/Terms/Security pages load: 
- CTA buttons route correctly: 

Evidence:
- Screens: 
- Notes:

---

## 2) Auth & safety (PASS/FAIL)
- Signup works and returns JWT: 
- Login works; wrong password returns 401: 
- Logout blacklists refresh token: 
- Session revoke works: 
- 2FA (if enabled) enforced: 

Evidence:
- API request/response snippets:
- Screens:
- Notes:

---

## 3) Billing & subscriptions (PASS/FAIL)
- Plans list correct (`/api/plans/`): 
- Checkout session creation: 
- Billing portal access: 
- Stripe webhook processing (valid signature): 
- Stripe webhook rejects invalid signature: 
- Cancel/reactivate/change plan consistent in UI + API: 

Evidence:
- Stripe event IDs:
- Webhook delivery logs:
- Notes:

---

## 4) Email notifications (PASS/FAIL)
- Email verification request triggers email:
- Password reset triggers email:
- No secret/token leakage in logs:

Evidence:
- Provider logs / console output:
- Redacted email content proof:
- Notes:

---

## 5) Scan pipeline (PASS/FAIL)
- Consent enforced in UI and backend:
- Create scan persists in DB:
- Status lifecycle is real (pending→running→completed/failed/stopped):
- Worker execution confirmed (no fake completion):
- Cancel is idempotent and audited:

Evidence:
- Scan IDs:
- Audit export excerpt:
- Notes:

---

## 6) Findings integrity (PASS/FAIL)
- Known-vulnerable target yields expected signals:
- Baseline target does not produce unjustified high/critical:
- UI counts match API and DB:

Evidence:
- Example finding IDs:
- Export files:
- Notes:

---

## 7) Exports (PASS/FAIL)
- PDF export contains real scan data:
- CSV/JSON exports are valid:
- Unauthorized export blocked:

Evidence:
- File sizes + sample rows (redacted):
- Notes:

---

## 8) Integrations/webhooks (PASS/FAIL)
- Test endpoint performs a real request:
- Webhook signature present when secret configured:
- Retry/disable behavior works:

Evidence:
- Captured webhook request headers (redacted):
- Notes:

---

## Summary
- Overall result: PASS / NO-GO
- Blockers (must-fix):
- Follow-ups (nice-to-have):


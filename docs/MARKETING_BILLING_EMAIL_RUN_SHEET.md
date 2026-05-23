# BugBounty Arsenal — Marketing, Billing, Email Run Sheet (Repeatable)

**Goal:** Validate all non-scan “product readiness” pillars end-to-end:
- Marketing/public pages
- Pricing correctness (no fake data)
- Stripe billing flows
- Email notifications (verification + password reset)

**Evidence:** Use `VERIFICATION_EVIDENCE_TEMPLATE.md` and the run log template `PRE_LAUNCH_RUN_LOG_TEMPLATE.md`.

---

## 0) Prerequisites

### Stripe
- Stripe in test mode (recommended for staging):
  - `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY` configured
  - Webhook signing secret configured
- Stripe CLI installed (recommended) for webhook replay:
  - https://stripe.com/docs/stripe-cli

### Email provider
- SendGrid configured for staging/prod-like runs.
- If SendGrid is not configured, the app may print emails to console; treat this as **non-launch-ready** until real delivery is verified.

---

## 1) Marketing & Public Website

### Page health
- [ ] Landing page loads (no 5xx)
- [ ] Pricing page loads and is consistent with backend plans
- [ ] Docs / Security / Privacy / Terms pages load
- [ ] Login/Signup pages load

### Messaging sanity (no misleading claims)
- [ ] “Plans/features” copy matches actual plan enforcement
- [ ] No claims of SSO/teams/integrations unless enabled

### Tracking (optional, if used)
- [ ] Analytics scripts do not break page load
- [ ] Consent/banner behavior is correct (if present)

---

## 2) Pricing correctness (no fake data)

**Check both UI and API:**
- [ ] Backend: `GET /api/plans/` returns plan names/prices/features
- [ ] UI: Pricing page displays the same plan list
- [ ] Any “discount/trial” is consistent with backend and Stripe setup

Evidence:
- Screenshot of pricing UI
- API response excerpt (redacted)

---

## 3) Stripe Billing E2E

### A) Checkout session
- [ ] UI starts checkout (or API endpoint creates checkout session)
- [ ] Redirect to Stripe Checkout works
- [ ] Successful payment returns user to the correct page

### B) Webhooks
- [ ] Stripe webhook endpoint receives the `checkout.session.completed` (or equivalent)
- [ ] Subscription status updates in DB
- [ ] UI reflects updated plan/subscription state

### C) Negative tests
- [ ] Invalid webhook signature is rejected
- [ ] Failed payment does not show success in UI
- [ ] Cancel subscription works; UI updates

**Stripe CLI suggestion (staging):**
- Use `stripe listen --forward-to http://localhost:8000/api/webhooks/stripe/`
- Trigger test events via `stripe trigger checkout.session.completed`

---

## 4) Email notifications E2E

### A) Email verification
- [ ] Request verification email
- [ ] Email is delivered to inbox (not only logs)
- [ ] Verification link/code succeeds

### B) Password reset
- [ ] Request password reset
- [ ] Email delivered
- [ ] Reset token/link works; user can log in with new password

### C) Security checks
- [ ] No JWT/refresh token printed in logs
- [ ] No API keys or signing secrets appear in emails

---

## 5) Go / No-Go criteria

**Go** if:
- Marketing pages load cleanly and claims match features
- Pricing is consistent UI↔API
- Stripe checkout + webhook updates are consistent
- Email delivery is confirmed in a real inbox (or provider logs)

**No-Go** if:
- Pricing shows data not backed by API
- Checkout succeeds but subscription state does not change
- Emails only appear in console logs (for staging/prod readiness)


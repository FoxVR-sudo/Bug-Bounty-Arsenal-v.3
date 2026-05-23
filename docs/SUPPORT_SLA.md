# Support & SLA

**Last updated:** 2026-01-18

This document defines the official support channels and response time expectations.

---

## Support Channels

- **Email Support:** configured via `SUPPORT_EMAIL`
- **Contact Form:** /contact (public page)
- **Security Reports:** configured via `SECURITY_EMAIL`
- **Sales / Enterprise:** configured via `SALES_EMAIL`

### Configuration
Set these environment variables in production:
- `PUBLIC_EMAIL_DOMAIN` (optional; default derives from `FRONTEND_URL`)
- `SUPPORT_EMAIL`, `SALES_EMAIL`, `SECURITY_EMAIL`, `PRESS_EMAIL`

---

## Response Time Expectations (SLA)

All times are **business hours**, unless otherwise specified.

| Plan | First Response | Target Resolution |
|---|---|---|
| Free | 2 business days | Best-effort |
| Pro | 1 business day | 5 business days |
| Enterprise | 4 hours (24/7 for P1/P0 incidents) | 2 business days |

### Severity Levels
- **P0 (Critical):** Platform down, data loss, security incident in progress.
- **P1 (High):** Major functionality broken, significant impact.
- **P2 (Medium):** Partial degradation or workaround exists.
- **P3 (Low):** Minor issues, cosmetic bugs.

### Communication
- Status updates are provided at least once per business day for open incidents.
- Enterprise incidents receive updates every 4 hours while P0/P1 is active.

---

## Support Intake Requirements

Include:
- Account email
- Affected scan IDs
- Timestamp & timezone
- Error messages or screenshots
- Steps to reproduce

---

## Exclusions

- Third‑party outages (e.g., upstream providers) are handled as best‑effort.
- Self‑inflicted misconfiguration is supported, but resolution time may vary.

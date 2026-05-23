# Ops Incident Runbook

**Last updated:** 2026-01-18

This runbook defines immediate response steps for common production incidents.

See also: docs/OBSERVABILITY_AND_ALERTS.md

---

## 1) DB Down / DB Unreachable

**Symptoms**
- `/readyz/` fails DB check
- Elevated 5xx on API
- Admin endpoints error with connection failures

**Immediate Actions**
1) Confirm DB health (host, disk, memory, connections).
2) Check recent deploys or migrations.
3) Scale down workers if they are flooding the DB.
4) Failover or restore from the last known good backup if required.

**Recovery**
- Verify DB integrity (admin restore verify-only).
- Re-enable traffic and monitor error rate.

---

## 2) Celery/Worker Down

**Symptoms**
- Scans stuck in `pending`/`running`
- Queue backlog increasing

**Immediate Actions**
1) Check broker health (Redis availability/latency).
2) Restart workers.
3) Validate queue consumers are connected.

**Recovery**
- Run cleanup task for stuck scans (celery-beat) and monitor audit logs.

---

## 3) Stripe Webhooks Failing

**Symptoms**
- Missing subscription updates
- Billing mismatches

**Immediate Actions**
1) Check Stripe webhook delivery logs.
2) Validate webhook signing secret.
3) Requeue failed events in Stripe.

**Recovery**
- Reconcile subscriptions with Stripe API and audit changes.

---

## 4) Elevated 5xx / Latency Spike

**Immediate Actions**
1) Check `/healthz/` and `/readyz/`.
2) Review logs and recent deploys (web + celery + celery-beat).
3) Roll back to the last known good build if needed.

**Recovery**
- Monitor error rate and latency for 30 minutes before closing incident.

---

## 6) Logging / Alerts Not Firing

**Symptoms**
- You see user-reported failures but dashboards are silent
- Missing logs from `web` / `celery`

**Immediate Actions**
1) Confirm `LOG_FORMAT` and runtime env vars are set as expected.
2) Check container log output (`docker logs bugbounty-web`, etc.).
3) Validate ingestion/forwarder health (if used).
4) Add a temporary high-signal log line (if needed) and redeploy.

---

## 5) Security Incident

**Immediate Actions**
1) Contain: isolate affected services.
2) Rotate keys/tokens if exposure is suspected.
3) Preserve logs and evidence.

**Recovery**
- Post-incident review with remediation plan.

---

## Post‑Incident Checklist

- Root cause analysis (RCA)
- Timeline of events
- Action items with owners and deadlines
- Customer communication summary

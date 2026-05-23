# Data Safety Runbook

**Last updated:** 2026-01-18

This runbook defines the migration/rollback plan and data retention policy for BugBounty Arsenal.

---

## 1) Migration & Rollback Plan

### Goals
- Zero data loss for schema changes.
- Safe, reversible deploys.
- Clear rollback steps for critical failures.

### Pre-deploy checklist
- **Backup**: create an admin backup via `/api/admin/database/backup/` and store it off-host.
- **Schema change review**: confirm migrations are additive or backward compatible.
- **Dry run**: apply migrations in staging with production-like data volume.
- **Rollback readiness**: confirm the last known-good image tag is available.

### Deployment sequence (safe default)
1) **Deploy code that is backward-compatible** with current schema (dual-read/write if needed).
2) **Apply migrations** using `python manage.py migrate`.
3) **Verify** app health (`/healthz/`, `/readyz/`) and a smoke test flow.
4) **Enable new behavior** behind flags (if applicable).

### Rollback procedure
Use this when a deployment introduces critical regressions.

1) **Stop traffic** or scale down workers if necessary.
2) **Rollback code** to the last known-good image/tag.
3) **Database rollback**:
   - Prefer **forward-fix** (new migration to correct data) if possible.
   - If a hard rollback is required:
     - Ensure `ALLOW_DB_RESTORE=true` on the admin service.
     - Call `/api/admin/database/restore/` with:
       - `backup_file`: path to verified backup
       - `apply: true`
       - `confirm: I_UNDERSTAND_THIS_WILL_OVERWRITE_DB`
4) **Verify** integrity using `/api/admin/database/restore/` (verify-only) before re-enabling traffic.

### Notes
- Non-SQLite engines require engine-specific backup/restore procedures.
- Avoid destructive migrations without a forward-compatible rollout plan.

---

## 2) Data Retention Policy

### Scope
- **Scan results** and derived artifacts (reports, exports).
- **Audit logs** for scans.

### Policy (baseline)
- **Free plan**: retain scans **7 days** after completion.
- **Pro plan**: retain scans **30 days** after completion.
- **Enterprise**: retain scans **90 days** after completion.
- **Exports**: delete alongside scan deletion.
- **Audit logs**: retain **12 months** minimum for compliance.

### Enforcement
- Scans have `expires_at` set at completion time based on plan.
- Periodic cleanup task deletes expired scans and their files.

### Operational notes
- If a retention policy changes, apply it to new scans; do not retroactively extend existing expirations unless explicitly required.
- Long-term archive (if needed) should be handled by a separate export/backup pipeline.

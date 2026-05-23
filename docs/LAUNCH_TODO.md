# Launch TODO (практичен списък)

## ✅ Готово
- [x] 2FA (TOTP + backup codes) — backend + UI
- [x] Enforce 2FA и на `/api/auth/login/` и на `/api/token/`
- [x] Production deploy (cPanel) + миграции
- [x] Production smoke test за 2FA

## ⏭️ Следващо (P0 преди платени потребители)
- [ ] Harden rate limiting coverage (преглед на всички публични endpoints + rates)
- [ ] Consent gate + audit log (не може да се стартира scan без съгласие)
- [ ] Verify plan enforcement backend (няма bypass през API)
- [ ] Set prod security headers/CORS (env-driven allowlist, X-Frame-Options и др.)
- [ ] Add monitoring + alert basics (5xx spike, worker offline, queue delay)
- [ ] DB backups + restore drill (поне 1 тест)
- [ ] Review npm audit vulnerabilities
- [ ] Go/No-Go checklist финално

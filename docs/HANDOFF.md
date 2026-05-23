# Handoff / Статус (Production) — 2FA + Deploy

Дата: 2026-01-15

## Какво е готово (фактологично)
- 2FA (TOTP + backup codes) е имплементирано и работи в production.
- 2FA е enforced и на двата входа:
  - `/api/auth/login/`
  - `/api/token/` (SimpleJWT obtain)
- Backup codes са еднократни (инвалидира се използваният код).
- Production deploy през cPanel е минал успешно:
  - code pull от `master`
  - `pip install -r requirements.txt`
  - `collectstatic`
  - `migrate`
  - рестарт на gunicorn
- Production smoke test 2FA през публичния домейн (HTTPS) е минал: signup → setup → confirm → login без OTP (401) → login с TOTP (200) → login с backup (200) → reuse backup (401).

## Важни детайли за production средата
- Сървър: cPanel SSH `bugbount@79.98.104.6:12545`
- App директория: `/home/bugbount/app`
- Виртуални среди:
  - реално използвана: `/home/bugbount/virtualenv/app/3.11` (Python 3.11)
  - налична, но проблемна за runtime: `/home/bugbount/virtualenv/app-py39` (Python 3.9)
- Deploy скрипт: `/home/bugbount/app/deploy.sh`
- Deploy log: `/home/bugbount/app/deploy.log`

## Блокер, който беше оправен
- `python manage.py migrate` на py39 падаше заради typing `dict | None` (Python 3.10+).
- Fix: заменено с `Optional[...]` (Python 3.9-compatible).

## Какво променихме последно (след 2FA)
- Добавихме по-широко rate limiting (signup, token refresh, email verify/reset + JWT obtain)
- В settings: добавени default throttle classes + нови throttle rates
- В settings: production defaults за CORS allowlist + X-Frame-Options (DENY когато DEBUG=False)

## Как продължаваме утре (без обяснения)
1) Проверка/настройка на production env vars в cPanel:
   - `DEBUG=False`
   - `ALLOWED_HOSTS=bugbounty-arsenal.com,www.bugbounty-arsenal.com`
   - `CSRF_TRUSTED_ORIGINS=https://bugbounty-arsenal.com,https://www.bugbounty-arsenal.com`
   - `FRONTEND_URL=https://bugbounty-arsenal.com`
   - `CORS_ALLOWED_ORIGINS=https://bugbounty-arsenal.com` (ако фронтенда е на същия домейн, пак е OK)
   - `SECURE_SSL_REDIRECT=True` + HSTS по избор
2) Deploy: `ssh ...` → `cd /home/bugbount/app && ./deploy.sh`
3) Продължаваме с P0 checklist:
   - Consent gate + audit log
   - Plan enforcement проверка (backend hard enforcement)
   - Monitoring/alerts
   - Backups/restore drill


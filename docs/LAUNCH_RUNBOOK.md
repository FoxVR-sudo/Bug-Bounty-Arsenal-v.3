# Launch Runbook (Production)

This document is the step-by-step runbook to ship BugBounty Arsenal to real users.

## Pre-flight

- Ensure you have the latest code:
  - `git fetch --all --prune`
  - `git checkout master`
  - `git pull --ff-only`
- Ensure required secrets are set on the server (.env or platform secrets):
  - `SECRET_KEY` (strong random)
  - `DEBUG=False`
   - Recommended observability:
      - `LOG_FORMAT=json` (centralized logging ingestion)
  - Optional but recommended hardening:
    - `SECURE_SSL_REDIRECT=True`
    - `SECURE_HSTS_SECONDS=31536000`
    - `SECURE_HSTS_INCLUDE_SUBDOMAINS=True`
    - `SECURE_HSTS_PRELOAD=True`

## Deploy (Docker Compose)

From the repo root on the server:

1) Build and start services:

```bash
docker compose up -d --build
```

2) Run migrations:

```bash
docker compose exec -T web python manage.py migrate
```

3) Optional: verify the users 2FA migration applied:

```bash
docker compose exec -T web python manage.py showmigrations users
```

4) Health check:

```bash
curl -fsS https://YOUR_DOMAIN/api/schema/ >/dev/null && echo "web health OK"

## Backup verify (recommended)

Before opening the service to real users:

1) Create a DB backup (admin endpoint) and store it off-host.
2) Run verify-only restore against the backup.

See: docs/DATA_SAFETY_RUNBOOK.md
```

## Deploy (cPanel + GitHub pull)

This is the production flow when you deploy to a server managed via cPanel (no Railway).

### 1) Pull latest code on the server

From the project directory on the server:

```bash
git fetch --all --prune
git checkout master
git pull --ff-only
```

### 2) Ensure environment variables are set

In cPanel this is typically either:
- cPanel → **Setup Python App** → **Environment Variables**, or
- an `.env` file in the project root (only if your hosting setup loads it).

Minimum recommended values:

```bash
DEBUG=False
SECRET_KEY=<strong-random>
ALLOWED_HOSTS=<your-domain>,www.<your-domain>
CSRF_TRUSTED_ORIGINS=https://<your-domain>,https://www.<your-domain>
SECURE_SSL_REDIRECT=True
CSRF_COOKIE_SECURE=True
SESSION_COOKIE_SECURE=True
```

### 3) Install/update Python dependencies

Use the same Python interpreter/venv that cPanel runs your app with.

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4) Run database migrations

```bash
python manage.py migrate
```

### 5) Static files

```bash
python manage.py collectstatic --noinput
```

### 6) Restart the app

This depends on your cPanel setup:
- If you use **Setup Python App**, click **Restart**.
- If you use Passenger, touch the restart file (example):

```bash
mkdir -p tmp
touch tmp/restart.txt
```

### 7) Health check

```bash
curl -fsS https://<your-domain>/api/schema/ >/dev/null && echo "web health OK"
```

## Smoke Test (2FA)

Run these checks with a non-admin test account.

1) Login without 2FA enabled → should succeed.
2) Enable 2FA:
   - Go to Profile → Security → Start 2FA Setup.
   - Scan QR in an authenticator app.
   - Enter a valid 6-digit code → confirm.
   - Save backup codes (download/print).
3) Logout.
4) Login again:
   - Without OTP → should be rejected with 2FA required.
   - With authenticator OTP → should succeed.
5) Backup codes:
   - Login using a backup code → should succeed.
   - Reuse the same backup code → should fail.
6) Regenerate backup codes (requires password + OTP) → should return a new set.
7) Disable 2FA (requires password + OTP) → login should no longer require OTP.

## Notes

- The new DB migration for 2FA fields is `users.0005_user_two_factor_fields`.
- If email provider env vars aren’t set, email actions will log to console (expected in non-prod).

# Production Issue Resolution - 2026-01-10

## Problem: HTTP 503 Errors on All API Endpoints

**Symptoms:**
```
XHRGET https://bugbounty-arsenal.com/api/plans/ [HTTP/2 503]
XHRGET https://bugbounty-arsenal.com/api/detector-categories/ [HTTP/2 503]
Failed to fetch plans: Request failed with status code 503
```

## Root Cause

1. **First Issue (Resolved)**: HTTP 404 - LiteSpeed wasn't proxying API requests
   - Solution: Created `.htaccess` with mod_rewrite rules to proxy `/api/*` to Django backend

2. **Second Issue (Resolved)**: HTTP 503 - Gunicorn (Django backend) not running
   - Gunicorn was stopped/crashed
   - Missing Python dependencies (`python-dotenv`, etc.)
   - Wrong virtualenv path

## Resolution Steps

### 1. Created `.htaccess` for LiteSpeed Proxy

**File**: `/home/bugbount/public_html/.htaccess`

```apache
# Proxy API requests to Django backend (Gunicorn on port 8000)
RewriteCond %{REQUEST_URI} ^/api/ [OR]
RewriteCond %{REQUEST_URI} ^/admin/
RewriteRule ^(.*)$ http://127.0.0.1:8000/$1 [P,L]

# All other requests serve from React build (SPA)
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^ index.html [L]
```

### 2. Fixed Python Environment

**Correct paths**:
- Project: `/home/bugbount/app/`
- Virtualenv: `/home/bugbount/virtualenv/app/3.11/`
- Python: `/home/bugbount/virtualenv/app/3.11/bin/python3.11`

**Installed missing dependencies**:
```bash
cd /home/bugbount/app
source /home/bugbount/virtualenv/app/3.11/bin/activate
pip install -r requirements.txt
```

### 3. Created Startup Script

**File**: `/home/bugbount/app/start_gunicorn.sh`

```bash
#!/bin/bash
cd /home/bugbount/app
source /home/bugbount/virtualenv/app/3.11/bin/activate

# Kill existing processes
pkill -f "gunicorn config.wsgi"
sleep 2

# Start Gunicorn
gunicorn config.wsgi:application \
    --bind 127.0.0.1:8000 \
    --workers 3 \
    --daemon \
    --access-logfile logs/gunicorn-access.log \
    --error-logfile logs/gunicorn-error.log \
    --pid gunicorn.pid

echo "Gunicorn started at $(date)"
```

## Verification

```bash
# Check Gunicorn is running
ps aux | grep gunicorn | grep -v grep
# Should show: 1 master + 3 workers

# Test API endpoints
curl https://bugbounty-arsenal.com/api/plans/
curl https://bugbounty-arsenal.com/api/detector-categories/
curl https://bugbounty-arsenal.com/api/scan-categories/
# All should return HTTP 200
```

## Result

✅ All API endpoints working  
✅ Frontend loading correctly  
✅ No more 404 or 503 errors  
✅ Gunicorn stable with 3 workers  

## Prevention

**Monitor script** (runs every 5 minutes via cron):
```bash
#!/bin/bash
if ! pgrep -f "gunicorn config.wsgi" > /dev/null; then
    /home/bugbount/app/start_gunicorn.sh
fi
```

Add to crontab:
```bash
*/5 * * * * /home/bugbount/app/monitor_gunicorn.sh >> /home/bugbount/app/logs/monitor.log 2>&1
```

## Notes

- Stripe cookie warnings are **normal** (third-party context)
- "Layout forced" warning is **normal** (CSS loading timing)
- Production uses LiteSpeed Web Server (not Apache/Nginx)
- Django runs on port 8000 (localhost only)
- Frontend served from `/home/bugbount/public_html/`

## Quick Commands

```bash
# Restart Gunicorn
ssh -p 12545 bugbount@79.98.104.6
./start_gunicorn.sh

# View logs
tail -f /home/bugbount/app/logs/gunicorn-error.log

# Check status
ps aux | grep gunicorn
```

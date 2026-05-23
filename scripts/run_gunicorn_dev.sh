#!/usr/bin/env bash
set -euo pipefail

# Dev helper: run Gunicorn against the Django WSGI entrypoint.
# Usage:
#   ./scripts/run_gunicorn_dev.sh
# Optional env:
#   DEBUG=1 ALLOWED_HOSTS=localhost,127.0.0.1
#
# Note: Activate your venv first if you're using one:
#   source ./venv/bin/activate

export DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE:-config.settings}

HOST=${GUNICORN_HOST:-127.0.0.1}
PORT=${GUNICORN_PORT:-8000}
WORKERS=${GUNICORN_WORKERS:-2}

exec python -m gunicorn config.wsgi:application \
  --bind "${HOST}:${PORT}" \
  --workers "${WORKERS}" \
  --access-logfile - \
  --error-logfile - \
  --log-level ${GUNICORN_LOG_LEVEL:-info}

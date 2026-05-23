# Observability & Alerts (Runbook)

**Last updated:** 2026-01-18

Цел: production-ready наблюдаемост (логове + базови алерти) без тежка инфраструктурна зависимост.

---

## 1) Logging

### App log format
- Поддържаме opt-in JSON формат за по-лесен ingestion.
- Препоръчителна настройка: `LOG_FORMAT=json` (иначе default е текстов формат).

### Минимален ingestion вариант (без отделен stack)
- Събиране на `docker logs` от `web`, `celery`, `celery-beat`.
- Централизиране чрез инфраструктурата (например cloud log sink / syslog / journald forwarder).

### Препоръчителен ingestion вариант (Loki/Grafana)
- Използвай Loki + Grafana (по избор) и forwarder (Promtail/Vector/Fluent Bit).
- Ако ползваш Docker: най-лесно е да forward-ваш container logs към Loki.

**Какво да търсим в логовете:**
- 5xx spike (API)
- `scan_failed` / task failures
- broker errors / redis connectivity
- export 413/429/503
- auth rate-limit/abuse

---

## 2) Metrics / Health checks

### Health endpoints
- Liveness: `/healthz/`
- Readiness: `/readyz/` (DB + optional broker)

### Минимални SLO сигнали
- Error rate: 5xx rate
- Latency: p95/p99
- Worker health: queue backlog / task age
- Scan failure rate (admin metrics endpoint)

---

## 3) Alerts (baseline)

### Critical (page)
- API 5xx rate > 2% за 5 мин
- `/readyz/` fail > 2 мин
- Celery worker offline / no heartbeats > 2 мин
- Redis down

### Warning (ticket)
- Elevated scan failure rate (spike)
- Export 413/429 spike
- Rate-limit spikes (potential abuse)

---

## 4) Suggested dashboards

- API health: requests/sec, 4xx/5xx, latency
- Celery: active workers, queue depth, task runtime
- Scans: started/completed/failed, avg duration, stuck cleanup counts
- Billing: 402/403 rates

---

## 5) Incident workflow

1) Confirm `/healthz/` + `/readyz/`
2) Check logs around incident window
3) Verify Redis + workers
4) Rollback if needed (see docs/DATA_SAFETY_RUNBOOK.md)
5) Post-incident: RCA + action items

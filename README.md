# BugBounty Arsenal v3

BugBounty Arsenal is a full-stack security testing platform for managing authorized web application scans, detector execution, evidence collection, and result triage from a single dashboard.

This repository is being prepared as a public-facing version of the project. Internal runbooks, deployment-only files, customer evidence, and local environment artifacts should stay out of the public release.

## Stack

- Django 6 and Django REST Framework
- React 18, React Query, React Router, Tailwind CSS
- Celery and Redis for async scan execution
- SQLite or PostgreSQL-backed persistence
- Docker Compose for local development

## Core capabilities

- Launch and monitor scans from a web dashboard
- Run detector-based checks for common web security issues
- Store findings, evidence metadata, and scan history
- Export results for reporting and triage workflows
- Manage authentication, verification, user profiles, and plan-based access

## Repository layout

- `config/` Django settings, ASGI, Celery, middleware, routing
- `detectors/` active and passive detector implementations
- `frontend/` React client application
- `scans/` scan models, tasks, APIs, exports, websocket updates
- `subscriptions/` plan and usage management
- `users/` authentication, profile, verification, integrations

## Quick start with Docker

```bash
cp .env.example .env
docker compose up --build
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

Frontend: `http://localhost:3000`

API: `http://localhost:8001/api`

## Local development

### Backend

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py runserver 0.0.0.0:8001
```

### Frontend

```bash
cd frontend
npm install
npm start
```

## Public release scope

The public repository intentionally omits most internal runbooks, launch checklists, and the private test suite used in day-to-day development.

## Public release notes

The public repo should exclude:

- evidence and generated scan artifacts
- private deployment scripts and environment-specific configs
- internal status notes, summaries, and migration scratch files
- local databases, keys, certificates, and editor state

This public release is intended to contain only development-safe source and documentation.

## Safety

Use this project only against systems you own or are explicitly authorized to test.

## License

MIT
# Contributing to BugBounty Arsenal

Thanks for contributing. This repository is the public, development-safe edition of BugBounty Arsenal.

## Before you open a PR

- Check existing issues and pull requests first.
- Keep changes focused and small.
- Do not include secrets, customer data, scan artifacts, or environment-specific files.
- Use only authorized targets when testing scanner behavior.

## Reporting bugs

Open an issue with:

- a clear description of the problem
- exact steps to reproduce it
- expected behavior and actual behavior
- relevant environment details such as OS, Python version, and Node version
- logs or screenshots when they help explain the issue

## Suggesting features

Feature requests are welcome. Good requests usually include:

- the problem being solved
- the expected user workflow
- why the feature belongs in the public repository
- any constraints or tradeoffs you already see

## Local setup

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

### Docker

```bash
cp .env.example .env
docker compose up --build
```

## Pull request guidelines

- Branch from `master`.
- Use descriptive branch names such as `fix/dashboard-plan-label` or `feat/new-detector`.
- Update documentation when behavior changes.
- Keep refactors separate from feature changes when possible.
- Include manual verification notes in the PR description.

## Code guidelines

- Follow the existing style of the surrounding code.
- Prefer small, reviewable changes over broad rewrites.
- Keep detector behavior explicit and avoid noisy false positives.
- Preserve safe defaults and consent-oriented behavior.

## Testing expectations

The public repository does not include the private day-to-day test suite. For changes you submit, include the narrowest verification you actually ran, for example:

- a focused manual UI verification
- a targeted Django command or smoke check
- a frontend build check
- a detector-specific reproduction against a safe local target

## Security

Do not use public GitHub issues for vulnerability disclosure. See `SECURITY.md` for the reporting process.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

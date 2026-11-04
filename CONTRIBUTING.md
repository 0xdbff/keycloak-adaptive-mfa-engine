# Contributing to Adaptive MFA

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository and create a branch from `development`.
2. Follow the setup instructions in the README to run the service locally.
3. Make your changes, add tests where applicable, and ensure all existing tests pass.
4. Open a pull request against `development` with a clear description of the change. Do not include customer hostnames, database names, or image tags.

## Development Setup

```bash
# Start the full stack (Keycloak + engine + redis + postgres)
cd config/keycloak
cp .env.example .env
docker compose up --build -d
```

See `config/keycloak/docker-compose.yml` and `docs/keycloak-setup.md` for details.

## Running Tests

```bash
pytest tests/unit -v

# Needs a migrated database, named by the POSTGRES_* variables.
# DB_TYPE=mssql runs the same tests on SQL Server.
alembic upgrade head
pytest tests/integration -v
```

## Code Style

- Python 3.11+, async/await throughout
- Pydantic v2 for schemas, SQLAlchemy 2.0 async ORM
- New risk checks go in `src/service/risk_evaluation/checks/`
- All new code must have corresponding unit tests in `tests/unit/`

## Database migrations

Migrations must apply on PostgreSQL (the default) and SQL Server (`DB_TYPE=mssql`). Run `alembic upgrade head` against both before opening a PR that touches `migrations/` or SQLAlchemy models.

CI runs `alembic check` on both databases, so autogenerate must propose nothing on a migrated database. The indexes in `HAND_MANAGED_INDEXES` (`migrations/env.py`) are excluded because Alembic cannot compare them. Change those by hand. Model defaults differ by `DB_TYPE`; Alembic does not compare them.

The Docker image installs from `requirements.lock`. CI does the same. If you add a package, pin it in both `requirements.txt` and `requirements.lock`.

## Pull Request Guidelines

- Keep PRs focused on a single concern
- Include a test for any bug fix or new feature
- Update relevant documentation if behavior changes

## Developer Certificate of Origin (DCO)

This project requires a DCO sign-off on every commit. By signing off, you
certify that you wrote the change or otherwise have the right to submit it
under the project's open-source license.

Add a `Signed-off-by` line to each commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Git can do this automatically with `git commit -s`.

By signing off you agree to the
[Developer Certificate of Origin](https://developercertificate.org/).

## Reporting Issues

Open a GitHub issue with a clear description, steps to reproduce, and the version you are running.

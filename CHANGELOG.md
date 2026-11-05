# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `MSSQL_POOL_SIZE` and `MSSQL_MAX_OVERFLOW` size the SQL Server connection pool. `MSSQL_AUTHENTICATION=ActiveDirectoryMsi` signs in with an Azure managed identity.
- `tests/integration` runs the login-scoring and monitoring queries against a real database, on PostgreSQL and SQL Server, in CI and before a release.
- `DB_TYPE=mssql` runs the engine against Azure SQL (or any SQL Server) in the same codebase as PostgreSQL. Postgres remains the default. Connection still uses the existing `POSTGRES_*` variables; ODBC Driver 18 is in the image for the SQL Server path.

### Changed

- The published image's lock file moves 60 packages: 54 upgraded and 6 added. The largest moves are FastAPI 0.109 to 0.162, Starlette 0 to 1 (0.35.1 to 1.10.0), Uvicorn 0.21 to 0.53, redis 5 to 8, and cryptography 44 to 50.
- Startup and shutdown run through a FastAPI lifespan handler, because Starlette 1 removed `add_event_handler`.
- CI installs `requirements.txt` and the image lock file in separate jobs, and fails when an installed version does not satisfy `requirements.txt`.

### Removed

- `POSTGRES_SCHEMA`. It was read and never used.

### Fixed

- Image lock file pins SQLAlchemy 2.0.54 so `mssql+aioodbc` loads (added in 2.0.23). CI installs from the same lock file and runs the unit suite against SQL Server.
- Boolean and keyset filters no longer compile to `col = 1 = 1` on SQL Server, so login scoring, configuration activation, VPN filters, and monitoring paging work there.
- Map buckets round once, at the configured precision, in a subquery, so SQL Server groups and places coordinates as PostgreSQL does. Rounding through 4 decimals first put 38.74996 in the 38.8 cell, and capped the precision at 4 decimals.
- `/health` and `/health/detail` answer within `HEALTH_CHECK_TIMEOUT` (3 seconds by default) when the database or Redis hangs, on both databases, and recover by the next probe once it is back. They could previously hold a probe for 15 seconds or more. Checks use their own connections, so a stuck check cannot hold a slot in the shared pool.
- Realm, group, and human-readable text columns are `NVARCHAR` with a case-sensitive UTF-8 collation on SQL Server. Hash columns use a binary collation.
- `wait_for_db.py` brace-escapes the ODBC password so generated Azure passwords containing `;`, `{`, or `}` can start the container.
- SQL Server connection pools default to 2 plus 2 overflow per worker, so the default four workers stay under Azure SQL Basic's limits of 30 concurrent workers and logins.
- Monitoring queries no longer fail with a collation conflict on a SQL Server database that uses the server's default collation.
- `auth_event` and `auth_process` cluster on time rather than a random UUID on SQL Server, so they do not fragment as they grow. The realm index on `auth_event` uses ascending keys for the same reason. The remaining secondary indexes need routine maintenance, described in `docs/environment-variables.md`.
- `alembic check` reports no changes on a migrated database, on either dialect, and CI enforces it.
- The release workflow runs the same tests as CI, from the same lock file the image uses.

## [1.1.0] - 2026-10-19

### Added

- `MONITORING_TRUSTED_READERS` lets a named service account read the read-only `/monitoring` endpoints of any realm, so one monitoring client in an admin realm can read every tenant realm
- `REDIS_USERNAME` for a Redis 6+ ACL user, and `REDIS_SSL` and `REDIS_SSL_CA_CERTS` for TLS to Redis

### Fixed

- `REDIS_PASSWORD` is sent to Redis, so the engine starts against a Redis that requires a password, and startup stops with a clear error when Redis cannot be reached or refuses the credentials
- Removed a check for LOGIN events with no open auth process that never ran; such events are stored as before

## [1.0.1] - 2026-09-22

### Added

- Risk evaluation engine with 19 configurable signals
- Local ML inference using K-Modes, DBSCAN, and histogram-based time profiling
- Weight-based and log-odds Bayesian scoring modes
- Device and network familiarity scoring
- Impossible travel detection
- VPN, proxy, and Tor detection using bundled IP databases
- Per-realm configuration for weights, allow-lists, and deny-lists
- Self-healing risk decay over repeated clean logins
- REST API with `POST /decision` and `POST /auth_context` endpoints
- Docker Compose stack with Keycloak, PostgreSQL, Redis, and Mailpit
- Alembic database migrations
- Bundled DB-IP Lite geolocation and ASN databases
- DB-IP CC BY 4.0 attribution in README
- Local dev credentials warning in README
- SECURITY.md, CODE_OF_CONDUCT.md, and CONTRIBUTING.md

[1.1.0]: https://github.com/DefensePoint/keycloak-adaptive-mfa-engine/releases/tag/v1.1.0
[1.0.1]: https://github.com/DefensePoint/keycloak-adaptive-mfa-engine/releases/tag/v1.0.1

# High-Availability Setup

This document explains how to run the AMFA stack in a multi-node, high-availability
configuration using `config/keycloak/docker-compose.ha.yml`.

## Overview

The HA stack extends the single-node quick-start with:

- **Two Keycloak nodes** clustered via embedded Infinispan and JDBC_PING. Sessions
  are replicated across both nodes, so killing either node does not log users out.
- **Two AMFA engine replicas** sharing the same PostgreSQL database and Redis
  instance. The engine is stateless between requests so any replica can serve any
  request.
- **nginx** as a TLS-terminating load balancer in front of both Keycloak nodes and
  both engine replicas. It gets the DNS alias `keycloak` on the internal network so
  all token issuer URLs remain identical to the single-node stack.

```
Browser / AMFA SPI
       │
       ▼
  nginx (:8443 HTTPS, :8095 HTTP)
  ┌────┴────┐              ┌────────┴────────┐
  │         │              │                 │
keycloak-1  keycloak-2   engine-1         engine-2
  │         │              │                 │
  └────┬────┘              └────────┬────────┘
       │                            │
   PostgreSQL  ◄───────────────────►  Redis
   (Keycloak DB + JDBC_PING + AMFA schema)
```

All host-side ports are identical to the single-node stack (`8443`, `8095`, `8025`,
`5433`, `6379`) so realm configuration, `/etc/hosts` entries and mkcert certificates
apply unchanged.

## Prerequisites

The prerequisites are the same as the single-node stack (see the main
[README](../README.md)):

- Docker and Docker Compose
- `keycloak` entry in `/etc/hosts` pointing to `127.0.0.1`
- mkcert installed and the certificate generated under `config/keycloak/certs/`

No additional setup is required.

## Running the HA stack

All commands below are run from the **repository root**.

If the single-node stack is running, stop it first:

```bash
docker compose -f config/keycloak/docker-compose.yml down
```

Copy the environment file if you have not done so already:

```bash
cp config/keycloak/.env.example config/keycloak/.env
```

Start the HA stack:

```bash
docker compose -f config/keycloak/docker-compose.ha.yml up --build -d
```

### Startup order

Docker Compose enforces the following dependency chain automatically:

1. `postgres`, `redis`, `mailpit` start and pass health checks
2. `providers` verifies or downloads the provider JARs (one-shot)
3. `keycloak-1` starts and imports the `test-amfa` realm
4. `adaptive_auth_1` runs Alembic migrations and starts the engine
5. `keycloak-2` starts and joins the Infinispan cluster (waits for keycloak-1 to
   be healthy to avoid a simultaneous realm-import race)
6. `adaptive_auth_2` starts after `adaptive_auth_1` is healthy (avoids the
   Alembic table-creation race on a fresh database)
7. `nginx` starts after both Keycloak nodes and both engine replicas are up

Keycloak-2 joining the cluster triggers an Infinispan session rebalance. You will
see log lines like `Finished rebalance with members [node1, node2]` in both
Keycloak containers when the cluster is ready.

### Verifying the stack

```bash
# All services healthy
docker compose -f config/keycloak/docker-compose.ha.yml ps

# AMFA engine (load balanced)
curl http://localhost:8095/health
# {"status":"ok","db":"ok","redis":"ok","ip_data":{"status":"ok"}}

# Keycloak via nginx
curl -sk -o /dev/null -w "%{http_code}\n" https://keycloak:8443/realms/master
# 200
```

### Verifying the Keycloak cluster

```bash
docker logs amfa-ha-keycloak-1-1 2>&1 | grep "Finished rebalance"
docker logs amfa-ha-keycloak-2-1 2>&1 | grep "Finished rebalance"
```

Both nodes should report `members [<node1>, <node2>]`.

## Direct node access (debugging)

Each Keycloak node exposes an HTTP port for debugging. Do not use these ports for
normal login flows — the token issuer would be `http://localhost:1808X` instead of
`https://keycloak:8443`, which breaks token signature verification in the engine.

| Node | Debug port |
|---|---|
| keycloak-1 | `http://localhost:18080` |
| keycloak-2 | `http://localhost:28080` |

## Testing failover

### Engine replica failover

```bash
# Kill one replica
docker stop amfa-ha-adaptive_auth_1-1

# Engine should still respond via the surviving replica
curl http://localhost:8095/health

# Restore
docker start amfa-ha-adaptive_auth_1-1
```

### Keycloak node failover

1. Log in at `https://keycloak:8443/realms/test-amfa/account`
2. Confirm you reach the account console
3. Kill one node:
   ```bash
   docker stop amfa-ha-keycloak-1-1
   ```
4. Reload the page in the browser

**Expected:** The page reloads (with a brief delay while nginx detects the failure
and retries the surviving node) and you remain logged in without being asked to
re-authenticate. This confirms that the Infinispan session replication is working.

5. Restore:
   ```bash
   docker start amfa-ha-keycloak-1-1
   ```

### Watching traffic distribution

```bash
docker logs -f amfa-ha-nginx-1
```

Each log line includes `upstream="<ip>:<port>"` showing which backend handled the
request. You should see requests alternating between both Keycloak nodes and both
engine replicas.

## What this setup does NOT cover

The following components remain single-node in this configuration. They are not
bottlenecks for a development or staging HA test, but a production deployment
should address them:

| Component | Current state | Production recommendation |
|---|---|---|
| PostgreSQL | Single node | Streaming replication (primary + standby) with a connection pooler such as PgBouncer or a managed service |
| Redis | Single node | Redis Sentinel (3 nodes) or Redis Cluster |
| nginx | Single node | Two nginx instances behind a floating IP (keepalived) or a cloud load balancer |
| mkcert TLS certificate | Self-signed, dev only | Certificate from a trusted CA or an internal PKI |

## Switching back to the single-node stack

```bash
docker compose -f config/keycloak/docker-compose.ha.yml down
docker compose -f config/keycloak/docker-compose.yml up -d
```

The two stacks use separate Docker volume names (`amfa_*` vs `amfa-ha_*`) so they
do not share data and can coexist on the same machine.

## Known limitations

**`start-dev` mode.** Both Keycloak nodes run in `start-dev` mode, which disables
some production hardening (theme caching, strict hostname checks). This is
intentional for a testable HA setup. A production deployment should use `start`
with a pre-built optimised image (`Dockerfile.keycloak`).
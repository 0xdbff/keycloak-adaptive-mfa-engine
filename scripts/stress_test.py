"""Load test for the AMFA engine, driven through a real Keycloak.

The engine accepts a login event only inside a JWT that Keycloak signed for
that user, so load cannot be faked from outside Keycloak. This script creates a
throwaway realm from config/keycloak/test-amfa-realm.json, with N users and a
direct-grant flow that runs the AMFA steps, and then logs those users in:

  login     Direct-grant logins (username + password) against Keycloak. The
            plugin calls /auth_context and /decision, and Keycloak sends the
            signed LOGIN or LOGIN_ERROR webhook, exactly as in a deployment.
  decision  /auth_context then /decision straight to the engine, with the
            realm's own service-account token. Loads the engine alone (no
            webhooks), to find its limit when Keycloak is not in the way.

The engine allows RATE_LIMIT_MAX_REQ decisions per user per window (4 a minute
by default), and Keycloak's brute-force check refuses a user's logins less than
a second apart. Each user is therefore logged in at most --per-user times a
minute, and more users give a higher ceiling. A 429 in the report means the
engine's limit was reached anyway.

Defaults match the shipped stack (config/keycloak/docker-compose.yml started
with the e2e overlay, project "amfa"):

  docker compose -p amfa -f config/keycloak/docker-compose.yml \\
      -f config/keycloak/docker-compose.e2e.yml up -d
  python3 scripts/stress_test.py --users 300 --duration 60

Without the e2e overlay Keycloak ignores X-Forwarded-For and every login comes
from one address. --engine-container and --db-container (docker) add the
engine's memory and CPU and a check of what it stored; leave them empty to skip.
In login mode the database check is what shows engine failures: the plugin
answers a failed /decision with the realm's fallback risk, so the logins still
succeed. The realm is removed at the end unless --keep is given, and so are
the engine rows it produced, when --db-container is set.

Needs Python 3.9+ and aiohttp.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import ssl
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from statistics import quantiles

import aiohttp

REPO = Path(__file__).resolve().parent.parent
REALM_EXPORT = REPO / "config/keycloak/test-amfa-realm.json"
DEFAULT_CA = REPO / "config/keycloak/certs/rootCA.pem"
LOGIN_CLIENT = "test-login"
ENGINE_CLIENT = "adaptive-auth-api"
FLOW_ALIAS = "amfa direct grant"
PASSWORD = "Stress-Test-1!"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
]
LANGUAGES = ["en-US", "es-ES", "fr-FR", "de-DE", "pt-PT"]
SCREENS = ["1920x1080", "1366x768", "1440x900", "1536x864", "390x844"]
# Public resolver addresses: real, routable, and spread over several countries,
# so the geo and network signals see plausible data.
IPS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "77.88.8.8", "77.88.8.1", "94.140.14.14",
    "94.140.15.15", "185.228.168.9", "185.228.169.9", "76.76.19.19", "76.223.122.150",
    "64.6.64.6", "64.6.65.6", "8.26.56.26", "8.20.247.20", "4.2.2.1", "4.2.2.2",
    "216.146.35.35", "216.146.36.36", "45.90.28.0", "45.90.30.0", "80.80.80.80",
    "80.80.81.81", "156.154.70.1", "156.154.71.1",
]


class Stats:
    def __init__(self):
        self.latency = defaultdict(list)  # kind -> seconds
        self.status = defaultdict(Counter)  # kind -> {status: n}
        self.outcome = defaultdict(Counter)  # kind -> {ok | refused | unexpected: n}
        self.lock = threading.Lock()

    def add(self, kind: str, status, seconds: float, outcome: str):
        with self.lock:
            self.latency[kind].append(seconds)
            self.status[kind][status] += 1
            self.outcome[kind][outcome] += 1


def ssl_context(args):
    if args.insecure:
        return False
    if args.ca_bundle and Path(args.ca_bundle).exists():
        return ssl.create_default_context(cafile=args.ca_bundle)
    return None  # the system trust store


async def admin_token(s: aiohttp.ClientSession, args) -> str:
    async with s.post(
        f"{args.kc_url}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": args.admin_user, "password": args.admin_password},
    ) as r:
        r.raise_for_status()
        return (await r.json())["access_token"]


def strip_ids(node):
    """Drop internal ids so Keycloak mints new ones; the export refers to
    everything by alias or name, so the copy stays consistent."""
    if isinstance(node, dict):
        return {k: strip_ids(v) for k, v in node.items() if k not in ("id", "containerId")}
    if isinstance(node, list):
        return [strip_ids(v) for v in node]
    return node


def execution(authenticator: str, priority: int) -> dict:
    return {"authenticator": authenticator, "authenticatorFlow": False, "autheticatorFlow": False,
            "requirement": "REQUIRED", "priority": priority, "userSetupAllowed": False}


def realm_representation(args, realm: str) -> dict:
    rep: dict = strip_ids(json.loads(REALM_EXPORT.read_text()))
    rep["realm"] = realm
    rep["enabled"] = True
    attrs = rep.setdefault("attributes", {})
    # Tokens must name the issuer the engine trusts, whatever address this
    # script uses to reach Keycloak.
    attrs["frontendUrl"] = args.issuer_base
    attrs["adaptiveAuthEndpoint"] = args.engine_url_from_keycloak
    rep["authenticationFlows"].append({
        "alias": FLOW_ALIAS, "description": "Direct grant with the AMFA steps",
        "providerId": "basic-flow", "topLevel": True, "builtIn": False,
        "authenticationExecutions": [
            execution("direct-grant-validate-username", 10),
            execution("direct-grant-validate-password", 20),
            execution("auth-context-authenticator", 30),
            execution("adaptive-auth", 40),
        ],
    })
    rep["directGrantFlow"] = FLOW_ALIAS
    for i in range(args.users):
        rep.setdefault("users", []).append({
            "username": f"stress-{i:05d}", "enabled": True, "emailVerified": True,
            "email": f"stress-{i:05d}@example.test", "firstName": "Stress", "lastName": f"User{i}",
            "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
        })
    return rep


async def create_realm(s, args, realm: str) -> list[dict]:
    tok = await admin_token(s, args)
    h = {"Authorization": f"Bearer {tok}"}
    async with s.post(f"{args.kc_url}/admin/realms", json=realm_representation(args, realm),
                      headers=h, timeout=aiohttp.ClientTimeout(total=900)) as r:
        if r.status not in (201, 204):
            raise SystemExit(f"could not create realm {realm} ({r.status}): {(await r.text())[:300]}")
    users = []
    while True:
        # A fresh token each time: importing thousands of users outlasts the
        # admin token's lifespan (60 s on master by default).
        h = {"Authorization": f"Bearer {await admin_token(s, args)}"}
        async with s.get(f"{args.kc_url}/admin/realms/{realm}/users", headers=h,
                         params={"search": "stress-", "first": len(users), "max": 1000,
                                 "briefRepresentation": "true"}) as r:
            r.raise_for_status()
            page = await r.json()
        users += [{"id": u["id"], "username": u["username"]} for u in page if u["username"].startswith("stress-")]
        if len(page) < 1000:
            break
    return sorted(users, key=lambda u: u["username"])


async def delete_realm(s, args, realm: str):
    tok = await admin_token(s, args)
    async with s.delete(f"{args.kc_url}/admin/realms/{realm}", headers={"Authorization": f"Bearer {tok}"}) as r:
        if r.status not in (204, 404):
            print(f"warning: could not delete realm {realm} ({r.status})")


class EngineToken:
    """The realm's own service-account token, renewed before it expires."""

    def __init__(self, s, args, realm):
        self.s, self.args, self.realm = s, args, realm
        self.value, self.expires, self.lock = None, 0.0, asyncio.Lock()

    async def get(self) -> str:
        async with self.lock:
            if time.time() < self.expires:
                return self.value
            if not getattr(self, "secret", None):
                tok = await admin_token(self.s, self.args)
                h = {"Authorization": f"Bearer {tok}"}
                base = f"{self.args.kc_url}/admin/realms/{self.realm}/clients"
                async with self.s.get(base, headers=h, params={"clientId": ENGINE_CLIENT}) as r:
                    cid = (await r.json())[0]["id"]
                async with self.s.get(f"{base}/{cid}/client-secret", headers=h) as r:
                    self.secret = (await r.json())["value"]
            async with self.s.post(
                f"{self.args.kc_url}/realms/{self.realm}/protocol/openid-connect/token",
                data={"grant_type": "client_credentials", "client_id": ENGINE_CLIENT, "client_secret": self.secret},
            ) as r:
                r.raise_for_status()
                body = await r.json()
            self.value = body["access_token"]
            self.expires = time.time() + body.get("expires_in", 60) * 0.8
            return self.value


class Schedule:
    """Hands out users so none is logged in more than per_user times a minute."""

    def __init__(self, users, per_user: float):
        self.gap = 60.0 / per_user
        self.queue = [(0.0, i) for i in range(len(users))]
        self.lock = asyncio.Lock()

    async def next(self) -> int:
        async with self.lock:
            due, i = self.queue.pop(0)
            self.queue.append((max(due, time.time()) + self.gap, i))
        delay = due - time.time()
        if delay > 0:
            await asyncio.sleep(delay)
        return i


def profile(i: int, roaming: float) -> dict:
    """A user's usual device and address, or now and then a different one."""
    rnd = random.Random(i)
    home = {"ua": rnd.choice(USER_AGENTS), "lang": rnd.choice(LANGUAGES),
            "screen": rnd.choice(SCREENS), "ip": IPS[i % len(IPS)]}
    if random.random() < roaming:
        home = {**home, "ip": random.choice(IPS), "ua": random.choice(USER_AGENTS)}
    return home


async def login_once(s, args, realm, user, stats: Stats) -> bool:
    wrong = random.random() < args.error_rate
    p = profile(int(user["username"][7:]), args.roaming)
    t0 = time.perf_counter()
    body = ""
    try:
        async with s.post(
            f"{args.kc_url}/realms/{realm}/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": LOGIN_CLIENT, "username": user["username"],
                  "password": "wrong-password" if wrong else PASSWORD},
            headers={"User-Agent": p["ua"], "Accept-Language": p["lang"], "X-Forwarded-For": p["ip"]},
        ) as r:
            body = await r.text()
            status = r.status
    except Exception as e:  # noqa: BLE001 - every failure counts, by kind
        status = type(e).__name__
    # Keycloak refuses a wrong password with 400 invalid_grant, before the AMFA
    # step runs. Anything other than that or a 200 is an error.
    if not wrong and status == 200:
        outcome = "ok"
    elif wrong and status in (400, 401) and '"invalid_grant"' in body:
        outcome = "refused"
    else:
        outcome = "unexpected"
    stats.add("login", status, time.perf_counter() - t0, outcome)
    return outcome != "unexpected"


async def decision_once(s, args, realm, user, token: EngineToken, stats: Stats):
    p = profile(int(user["username"][7:]), args.roaming)
    h = {"Authorization": f"Bearer {await token.get()}"}
    ctx = {"client": LOGIN_CLIENT, "ip_address": p["ip"], "user_agent": p["ua"],
           "system_language": p["lang"], "screen_resolution": p["screen"]}
    t0 = time.perf_counter()
    try:
        async with s.post(f"{args.engine_url}/auth_context", json=ctx, headers=h) as r:
            body = await r.json(content_type=None)
            status = r.status
    except Exception as e:  # noqa: BLE001
        status, body = type(e).__name__, None
    stats.add("auth_context", status, time.perf_counter() - t0, "ok" if status == 200 else "unexpected")
    if status != 200:
        return False
    req = {**ctx, "event_id": str(uuid.uuid4()), "group_id": "default", "realm_id": realm,
           "user_id": user["id"], "auth_context_hash": (body or {}).get("hash")}
    t0 = time.perf_counter()
    try:
        async with s.post(f"{args.engine_url}/decision", json=req, headers=h) as r:
            await r.read()
            status = r.status
    except Exception as e:  # noqa: BLE001
        status = type(e).__name__
    stats.add("decision", status, time.perf_counter() - t0, "ok" if status == 200 else "unexpected")
    return status == 200


async def warm_up(s, args, token: EngineToken):
    """One request before the load, so the token is known to work. The engine
    fetches a new realm's OIDC discovery on the first token it sees and answers
    503 to a burst beyond DISCOVERY_MAX_WAITERS meanwhile; that cold start is
    not what this measures (see --ramp)."""
    ctx = {"client": LOGIN_CLIENT, "ip_address": IPS[0], "user_agent": USER_AGENTS[0],
           "system_language": LANGUAGES[0], "screen_resolution": SCREENS[0]}
    status = None
    for _ in range(20):
        async with s.post(f"{args.engine_url}/auth_context", json=ctx,
                          headers={"Authorization": f"Bearer {await token.get()}"}) as r:
            await r.read()
            status = r.status
        if status == 200:
            return
        await asyncio.sleep(0.5)
    raise SystemExit(f"the engine does not accept the realm's token (last status {status})")


async def run_load(s, args, realm, users, stats: Stats) -> float:
    schedule = Schedule(users, args.per_user)
    token = EngineToken(s, args, realm) if args.mode == "decision" else None
    if token:
        await warm_up(s, args, token)
    pace = args.workers / args.rate if args.rate else 0.0
    end = time.time() + args.duration

    async def worker(n: int):
        # Start the workers over --ramp seconds: each engine worker process
        # fetches a new realm's OIDC discovery on its own first request.
        await asyncio.sleep(n * args.ramp / args.workers)
        while time.time() < end:
            t = time.time()
            user = users[await schedule.next()]
            if time.time() >= end:
                break
            if args.mode == "login":
                ok = await login_once(s, args, realm, user, stats)
            else:
                ok = await decision_once(s, args, realm, user, token, stats)
            if args.verbose:
                print(f"{user['username']}: {'ok' if ok else 'FAILED'}")
            if pace:
                await asyncio.sleep(max(0.0, pace - (time.time() - t)))

    t0 = time.time()
    await asyncio.gather(*(worker(n) for n in range(args.workers)))
    return time.time() - t0


class DockerStats(threading.Thread):
    """Samples a container's memory and CPU while the load runs."""

    def __init__(self, container: str):
        super().__init__(daemon=True)
        self.container, self.mem, self.cpu, self.done = container, [], [], threading.Event()

    def run(self):
        while not self.done.is_set():
            out = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}|{{.CPUPerc}}",
                                  self.container], capture_output=True, text=True).stdout.strip()
            if "|" in out:
                mem, cpu = out.split("|")
                self.mem.append(to_mib(mem.split("/")[0].strip()))
                self.cpu.append(float(cpu.rstrip("%") or 0))
            self.done.wait(2)


def to_mib(text: str) -> float:
    units = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "kB": 1 / 1000, "MB": 1, "GB": 1000, "B": 1 / 2 ** 20}
    for unit, factor in units.items():
        if text.endswith(unit) and text[: -len(unit)].replace(".", "", 1).isdigit():
            return float(text[: -len(unit)]) * factor
    return 0.0


def psql(args, sql: str) -> list[list[str]]:
    out = subprocess.run(["docker", "exec", args.db_container, "psql", "-U", args.db_user, "-d", args.db_name,
                          "-AtF", "|", "-c", sql], capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(out.stderr.strip())
    return [line.split("|") for line in out.stdout.splitlines() if line]


def stored(args, realm: str) -> dict:
    r = realm.replace("'", "''")
    return {
        "decisions": {k: int(n) for k, n in psql(args, f"SELECT final_status, count(*) FROM auth_process "
                                                       f"WHERE realm_id = '{r}' GROUP BY 1")},
        "events": {(t, linked == "t"): int(n) for t, linked, n in psql(
            args, f"SELECT event_type, auth_process IS NOT NULL, count(*) FROM auth_event "
                  f"WHERE realm_id = '{r}' GROUP BY 1, 2")},
    }


def purge(args, realm: str):
    r = realm.replace("'", "''")
    psql(args, f"DELETE FROM auth_event WHERE realm_id = '{r}'")
    psql(args, f"DELETE FROM auth_process WHERE realm_id = '{r}'")


def pct(values, q):
    if len(values) < 2:
        return values[0] if values else 0.0
    return quantiles(values, n=100, method="inclusive")[q - 1]


def report(args, stats: Stats, elapsed: float, docker: DockerStats | None, db: dict | None) -> int:
    problems = 0
    print(f"\n== {args.mode} mode, {args.workers} workers, {args.users} users, {elapsed:.1f}s")
    for kind, lat in stats.latency.items():
        st = stats.status[kind]
        ms = [v * 1000 for v in lat]
        print(f"{kind}: {len(lat)} requests, {len(lat) / elapsed:.1f}/s; {dict(stats.outcome[kind])}; "
              f"statuses {dict(st)}")
        print(f"  latency ms: p50 {pct(ms, 50):.0f}  p90 {pct(ms, 90):.0f}  p95 {pct(ms, 95):.0f}  "
              f"p99 {pct(ms, 99):.0f}  max {max(ms):.0f}")
        unexpected = stats.outcome[kind]["unexpected"]
        if unexpected:
            print(f"  {unexpected} unexpected responses")
            problems += 1
        if st.get(429):
            print("  429: the engine's per-user rate limit was hit; add users or lower --per-user")
        if st.get(503):
            print("  503: the engine could not verify tokens. A burst for a realm whose OIDC discovery is not"
                  " cached yet gets 503 past DISCOVERY_MAX_WAITERS; if it lasts, Keycloak is unreachable")
    if docker and docker.mem:
        print(f"engine container: memory peak {max(docker.mem):.0f} MiB (start {docker.mem[0]:.0f}), "
              f"CPU avg {sum(docker.cpu) / len(docker.cpu):.0f}% peak {max(docker.cpu):.0f}%")
    if db is not None:
        print(f"engine stored: decisions {db['decisions']}; events "
              + ", ".join(f"{t} {'linked' if linked else 'unlinked'} {n}" for (t, linked), n in sorted(db["events"].items())))
        if args.mode == "login":
            # A successful login closes its own decision as LOGIN; a wrong
            # password is refused before the AMFA step, so its LOGIN_ERROR has
            # no decision to link to.
            ok = stats.outcome["login"]["ok"]
            denied = stats.outcome["login"]["refused"]
            checks = [
                ("decisions closed as LOGIN", db["decisions"].get("LOGIN", 0), ok),
                ("decisions left open", sum(n for k, n in db["decisions"].items() if k != "LOGIN"), 0),
                ("LOGIN events linked", db["events"].get(("LOGIN", True), 0), ok),
                ("LOGIN events unlinked", db["events"].get(("LOGIN", False), 0), 0),
                ("LOGIN_ERROR events", sum(n for (t, _), n in db["events"].items() if t == "LOGIN_ERROR"), denied),
            ]
        else:
            # No webhooks in this mode: every scored request leaves its
            # decision open, and nothing else is written.
            ok = stats.outcome["decision"]["ok"]
            checks = [
                ("decisions left open", db["decisions"].get("pre-auth", 0), ok),
                ("decisions closed", sum(n for k, n in db["decisions"].items() if k != "pre-auth"), 0),
                ("events", sum(db["events"].values()), 0),
            ]
        for name, got, want in checks:
            flag = "ok" if got == want else "MISMATCH"
            problems += flag != "ok"
            print(f"  {name}: {got} (expected {want}) {flag}")
    return 1 if problems else 0


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--mode", choices=["login", "decision"], default="login")
    p.add_argument("--users", type=int, default=300, help="users in the throwaway realm (default 300)")
    p.add_argument("--workers", type=int, default=16, help="concurrent workers (default 16)")
    p.add_argument("--duration", type=int, default=60, help="seconds of load (default 60)")
    p.add_argument("--ramp", type=float, default=2, help="seconds over which the workers start (default 2); 0 starts them at once, a cold-start burst that also provokes races between simultaneous first logins")
    p.add_argument("--rate", type=float, default=0, help="total requests per second to aim for; 0 = as fast as allowed")
    p.add_argument("--per-user", type=float, default=3, help="logins per user per minute (default 3, under the engine's 4)")
    p.add_argument("--error-rate", type=float, default=0.1, help="share of logins with a wrong password (login mode)")
    p.add_argument("--roaming", type=float, default=0.2, help="share of logins from another address and browser")
    p.add_argument("--kc-url", default="https://localhost:8443", help="Keycloak as this script reaches it")
    p.add_argument("--issuer-base", default="https://keycloak:8443", help="Keycloak base URL the engine trusts (OIDC_TRUSTED_BASE_URLS)")
    p.add_argument("--engine-url", default="http://localhost:8095", help="engine as this script reaches it (decision mode)")
    p.add_argument("--engine-url-from-keycloak", default="http://adaptive_auth", help="engine as Keycloak reaches it")
    p.add_argument("--admin-user", default="admin")
    p.add_argument("--admin-password", default="admin")
    p.add_argument("--ca-bundle", default=str(DEFAULT_CA), help="CA that signed Keycloak's certificate")
    p.add_argument("--insecure", action="store_true", help="do not verify Keycloak's certificate")
    p.add_argument("--engine-container", default="amfa-adaptive_auth-1", help="sample memory/CPU; empty to skip")
    p.add_argument("--db-container", default="amfa-postgres-1", help="check what the engine stored; empty to skip")
    p.add_argument("--db-name", default="adaptive_mfa")
    p.add_argument("--db-user", default="keycloak")
    p.add_argument("--settle", type=int, default=10, help="seconds to wait for webhooks before checking the database")
    p.add_argument("--keep", action="store_true", help="keep the realm and the engine rows")
    p.add_argument("-v", "--verbose", action="store_true", help="print every request")
    return p.parse_args()


async def main(args) -> int:
    realm = f"amfa-stress-{uuid.uuid4().hex[:8]}"
    if args.db_container:
        psql(args, "SELECT 1")  # fail before the load, not after it
    # Drop idle connections before the server does (uvicorn closes them after
    # 5 s), or a request can go out on a socket the engine has just closed.
    conn = aiohttp.TCPConnector(limit=args.workers * 2, ssl=ssl_context(args), keepalive_timeout=2)
    async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=60)) as s:
        docker = DockerStats(args.engine_container) if args.engine_container else None
        try:
            print(f"creating realm {realm} with {args.users} users...")
            users = await create_realm(s, args, realm)
            print(f"ceiling from --per-user: {len(users) * args.per_user / 60:.1f} per second")
            stats = Stats()
            if docker:
                docker.start()
            elapsed = await run_load(s, args, realm, users, stats)
            if docker:
                docker.done.set()
            db = None
            if args.db_container:
                await asyncio.sleep(args.settle)
                db = stored(args, realm)
            elif args.mode == "login":
                print("note: no database check, so engine failures do not show here (the plugin falls back)")
            return report(args, stats, elapsed, docker, db)
        finally:
            if docker:
                docker.done.set()
            if not args.keep:
                await delete_realm(s, args, realm)
                if args.db_container:
                    purge(args, realm)
                else:
                    print(f"note: the engine rows of realm {realm} are left in place (no --db-container)")


if __name__ == "__main__":
    sys.exit(asyncio.run(main(parse_args())))

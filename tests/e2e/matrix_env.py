"""Setting up and tearing down an isolated environment for one matrix run.

Three jobs, in the order they matter.

**Preflight.** Refuse to run against a stack that cannot produce meaningful rows, and
say precisely what is wrong. Every check here corresponds to a way a run has already
been silently invalidated, so a clear failure now is cheaper than a confusing matrix
later.

**A throwaway realm.** Each run gets its own realm, cloned from the shipped
test-amfa export, and deletes it afterwards. Nothing the suite does touches a realm a
human is using. The alternative, mutating a shared realm and restoring it, was
rejected after a single admin PUT replaced the realm's attribute map rather than
merging it, removing `fallbackRisk` and breaking every login in that realm.

**Its own scoring parameters.** The suite writes the weights and allow/deny lists it
scores against, rather than inheriting them. This is not a preference. A realm with no
parameters falls back to `default`/`default`, and `DEFAULT_DECISION_PARAMS` ships with
all nineteen signals `disabled: True`, so an inherited configuration would produce a
matrix where no signal ever fires and every row reads the same. Owning the spec also
means the expected levels are determined by this file rather than by whatever someone
last edited in the database, which is what makes a recorded run replayable on another
machine.
"""

import hashlib
import json
import os
import pathlib
import subprocess
import time
import uuid

import requests

from tests.e2e.e2e_common import (
    COMPOSE_PROJECT,
    DOCKER_ENGINE,
    DOCKER_KEYCLOAK,
    DOCKER_MAILPIT,
    DOCKER_PG,
    DOCKER_REDIS,
)
from tests.e2e.matrix_lib import (
    KC_BASE,
    MAILPIT,
    admin_token,
    IS_MSSQL,
    psql,
)

# The command a failing preflight tells the operator to run. No -p flag: the project
# name is declared in the compose file, so passing one here could only contradict it.
COMPOSE_UP = (
    "    docker compose -f config/keycloak/docker-compose.yml "
    "-f config/keycloak/docker-compose.e2e.yml up -d"
)

ENGINE_BASE = os.getenv("E2E_ENGINE_BASE", "http://localhost:8095")

# Realm attributes the SPI reads, spelled exactly as AdaptiveAuthUtils declares them.
# Named here rather than inline so a rename on the Java side is one edit on this side,
# and so the resilience tests do not carry bare strings whose meaning is not obvious.
ADAPTIVE_AUTH_ENDPOINT = "adaptiveAuthEndpoint"
FALLBACK_RISK_ATTRIBUTE = "fallbackRisk"
FAILURE_MODE_ATTRIBUTE = "adaptiveAuthFailureMode"
REALM_EXPORT = pathlib.Path(
    os.getenv(
        "E2E_REALM_EXPORT",
        pathlib.Path(__file__).resolve().parents[2] / "config/keycloak/test-amfa-realm.json",
    )
)

# Weights the matrix scores against. A deliberate 1/2/3 spread so the weight bands
# (3, 6) can be probed from both sides: a single weight-3 signal lands exactly on the
# band 2 boundary, and two of them reach band 3.
#
# The allow and deny entries exist for the override rows. The addresses are chosen so
# that a deny row cannot be confused with a geo row: 203.0.113.9 is in TEST-NET-3 and
# resolves as non-public, so it carries no country of its own.
MATRIX_WEIGHTS = {
    "client": 1,
    "browser": 1,
    "screen_resolution": 1,
    "time_interval": 1,
    "anonymous_detection": 1,
    "login_failure": 1,
    "impossible_travel": 1,
    "ip_address": 2,
    "device": 2,
    "operating_system": 2,
    "country_name": 2,
    "system_language": 2,
    "inactive_account": 2,
    "concurrent_session": 2,
    "geolocation_cluster_label": 2,
    "date_time": 3,
    "event_cluster_label": 3,
    "recent_account_change": 3,
    "geo_loc": 3,
}

MATRIX_LISTS = {
    "ip_address": {"blacklist": ["203.0.113.9"], "whitelist": ["203.0.113.7"]},
    "country_name": {"blacklist": ["KR"], "whitelist": ["IN"]},
}

# geo_loc is disabled because it is unwired to any check, so enabling it would add a
# weight-3 signal that can never fire and would silently shift every band.
MATRIX_DISABLED = {"geo_loc"}

# Deliberately empty. The shipped realm gives date_time an allow window of 09:00-05:00
# and a deny window of 10:00-11:30, which makes a run's outcome depend on the clock:
# the same row behaves differently at 10:30 than at 14:00. Time-of-day is tested by
# shifting the seeded history instead, which is wall-clock independent.
MATRIX_TIME_WINDOWS: dict = {}

# The matrix scores in weight mode, pinned per realm rather than relying on the
# deployment's SCORING_MODE. Writing the parameter set replaces the __meta that holds
# this, so it has to be written after, and the engine default is bayesian: without
# pinning it a run would silently score against a different model than the baseline it
# is compared to.
# The scoring mode a run pins. "weight" is the matrix default; "bayesian" is the
# engine's deployment default (SCORING_MODE in the container), which is why it gets its
# own baseline rather than being left uncovered.
DEFAULT_SCORING_MODE = "weight"
SCORING_MODES = ("weight", "bayesian")


def scoring_config(mode: str = DEFAULT_SCORING_MODE) -> dict:
    if mode not in SCORING_MODES:
        raise ValueError(f"unknown scoring mode {mode!r}, expected one of {SCORING_MODES}")
    return {"mode": mode}


# Kept for callers that only ever meant the default.
MATRIX_SCORING = scoring_config()


class PreflightError(RuntimeError):
    """The stack cannot produce a meaningful run, with the reason and the fix."""


def _containers() -> dict:
    out = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
        capture_output=True, text=True, timeout=30,
    )
    found = {}
    for line in out.stdout.splitlines():
        if "\t" in line:
            name, status = line.split("\t", 1)
            found[name] = status
    return found


def preflight() -> dict:
    """Assert the stack can produce a meaningful run. Raises PreflightError if not.

    Returns a dict of what it observed, which goes into the run artifact so a recorded
    run carries the conditions it was produced under.
    """
    problems = []
    observed = {}

    running = _containers()
    for container in (DOCKER_KEYCLOAK, DOCKER_ENGINE, DOCKER_PG,
                      DOCKER_REDIS, DOCKER_MAILPIT):
        if container not in running:
            problems.append(
                f"container {container} is not running. Start the stack with:\n"
                f"{COMPOSE_UP}\n"
                f"  (expected names derive from compose project {COMPOSE_PROJECT!r}; "
                f"running: {sorted(running) or 'none'})"
            )
    observed["containers"] = running

    # The engine, and whether its IP data loaded. A matrix row that asserts a country
    # is meaningless if no geo database is present, and the failure would surface as a
    # wrong risk level rather than a missing database.
    try:
        health = requests.get(f"{ENGINE_BASE}/health", timeout=10).json()
        observed["engine_health"] = health
        if health.get("status") != "ok":
            problems.append(f"engine /health is {health.get('status')}: {health}")
        ip_data = (health.get("ip_data") or {}).get("status")
        if ip_data not in ("ok", "degraded"):
            problems.append(
                f"engine reports ip_data status {ip_data!r}; the geo and anonymiser "
                f"rows cannot resolve. Rebuild the image so the bundle is present."
            )
    except Exception as exc:
        problems.append(f"engine /health unreachable at {ENGINE_BASE}: {exc}")

    # X-Forwarded-For has to be trusted or six of the nineteen signals cannot be
    # driven at all, and the rows that depend on them would quietly measure the
    # Docker gateway address instead of the one the row specifies.
    try:
        out = subprocess.run(
            ["docker", "exec", DOCKER_KEYCLOAK, "sh", "-lc", "echo $KC_PROXY_HEADERS"],
            capture_output=True, text=True, timeout=30,
        )
        proxy_headers = out.stdout.strip()
        observed["kc_proxy_headers"] = proxy_headers
        if "xforwarded" not in proxy_headers:
            problems.append(
                "Keycloak does not trust X-Forwarded-For, so the ip_address, "
                "country_name, anonymous_detection, impossible_travel and "
                "geolocation_cluster_label rows cannot be driven. Restart the stack "
                "with the e2e overlay:\n"
                f"{COMPOSE_UP} keycloak"
            )
    except Exception as exc:
        problems.append(f"could not read Keycloak's environment: {exc}")

    try:
        requests.get(f"{MAILPIT}/api/v1/messages", timeout=8).raise_for_status()
        observed["mailpit"] = "reachable"
    except Exception as exc:
        problems.append(
            f"Mailpit unreachable at {MAILPIT}: {exc}. Untrained users are asked for "
            f"an email code, so training cannot complete without it."
        )

    if not REALM_EXPORT.is_file():
        problems.append(f"realm export not found at {REALM_EXPORT}")

    # The engine's own default configuration must exist, because a realm with no
    # parameters of its own falls back to it and a missing fallback raises mid-login.
    default_params = psql(
        "select count(*) from decision_params_config "
        f"where realm_id='default' and group_id='default' and is_active = {1 if IS_MSSQL else 'true'};"
    )
    observed["default_params_rows"] = default_params
    if default_params.strip() not in ("1",):
        problems.append(
            f"expected exactly one active default/default parameter set, found "
            f"{default_params!r}. The engine creates it at startup; check its logs."
        )

    observed["swept_realms"] = sweep_orphan_realms()

    if problems:
        raise PreflightError(
            "the stack is not ready for a matrix run:\n\n  - "
            + "\n\n  - ".join(problems)
        )
    return observed


def matrix_params(realm_id: str = "default", group_id: str = "default",
                  overrides: dict | None = None) -> list:
    """The parameter set the matrix scores against, as the settings API expects it.

    ``realm_id`` is part of the wire contract (ParameterAssignment requires it), so
    the fingerprint uses the placeholder default and the write substitutes the run's
    realm. Otherwise the fingerprint would change on every run and never match a
    recorded baseline.

    ``overrides`` lets a test build a realm that differs from the matrix's in a stated
    way, which several coverage families need and none of them should do by editing
    module constants. Recognised keys:

        disabled      parameter names to switch off, ADDED to MATRIX_DISABLED
        enabled       parameter names to switch on, REMOVED from MATRIX_DISABLED
        weights       per-parameter weight overrides, merged over MATRIX_WEIGHTS
        lists         per-parameter allow/deny lists, merged over MATRIX_LISTS
        inactive_days the dormancy threshold, replacing the default 40

    Everything merges, so a test states only its difference and a change to the matrix
    defaults still reaches it. `disabled` adds rather than replaces on purpose: the
    first version replaced the set, so a test switching off event_cluster_label
    silently switched geo_loc back *on* and would have measured a signal it never
    meant to enable.
    """
    overrides = overrides or {}
    disabled = (set(MATRIX_DISABLED) | set(overrides.get("disabled") or ())) - set(
        overrides.get("enabled") or ()
    )
    weights = {**MATRIX_WEIGHTS, **(overrides.get("weights") or {})}
    lists = {**MATRIX_LISTS, **(overrides.get("lists") or {})}
    inactive_days = overrides.get("inactive_days", 40)

    params = []
    for name, weight in weights.items():
        entry = lists.get(name, {})
        params.append({
            "realm_id": realm_id,
            "group_id": group_id,
            "parameter_name": name,
            "weight": weight,
            "disabled": name in disabled,
            "whitelist": entry.get("whitelist", []),
            "blacklist": entry.get("blacklist", []),
            "inactive_days": inactive_days if name == "inactive_account" else None,
        })
    return params


def config_fingerprint(mode: str = DEFAULT_SCORING_MODE,
                       overrides: dict | None = None) -> str:
    """A hash of everything that determines what level a row should produce.

    Recorded with each run so replaying a baseline against a differently configured
    engine fails with "the configuration moved" rather than twenty puzzling rows.

    The mode is part of the material, so the weight and bayesian baselines cannot be
    compared against each other by accident: the fingerprint guard rejects it before
    any row runs.
    """
    material = {
        "params": matrix_params(overrides=overrides),
        "scoring": scoring_config(mode),
        "env": _engine_scoring_env(),
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()[:32]


def engine_setting(name: str) -> int:
    """One engine setting, read from the running container.

    Used by the choreographed rows so they cross the threshold the deployment
    actually has rather than a number copied into the test, which would silently
    stop crossing it if the deployment changed. Cached because these rows ask for
    the same few values and each read is a container exec.
    """
    if name not in _SETTING_CACHE:
        script = (
            "from src.core.config import environment as e\n"
            f"print(getattr(e, {name!r}))\n"
        )
        out = subprocess.run(
            ["docker", "exec", "-w", "/app", DOCKER_ENGINE, "python", "-c", script],
            capture_output=True, text=True, timeout=60,
        )
        raw = out.stdout.strip().splitlines()
        if not raw:
            raise PreflightError(
                f"could not read {name} from the engine: {out.stderr.strip()}"
            )
        _SETTING_CACHE[name] = int(raw[-1])
    return _SETTING_CACHE[name]


_SETTING_CACHE: dict = {}


def _engine_scoring_env() -> dict:
    """The engine-side settings that move risk levels, read from the container."""
    script = (
        "import json\n"
        "from src.core.config import environment as e\n"
        "print(json.dumps({\n"
        "  'SCORING_MODE': e.SCORING_MODE,\n"
        "  'WEIGHT_RISK_BANDS': list(e.WEIGHT_RISK_BANDS),\n"
        "  'MIN_AUTH_EVENTS': e.MIN_AUTH_EVENTS,\n"
        "  'HAZARD_CHANGED_PARAMS_THRESHOLD': e.HAZARD_CHANGED_PARAMS_THRESHOLD,\n"
        "  'HAZARD_FAILED_ATTEMPTS_THRESHOLD': e.HAZARD_FAILED_ATTEMPTS_THRESHOLD,\n"
        "  'DEFAULT_RISK_LEVEL': e.DEFAULT_RISK_LEVEL,\n"
        "  'FALLBACK_RISK_LEVEL': e.FALLBACK_RISK_LEVEL,\n"
        "  'DROP_DOWN_DECAY_DAYS': e.DROP_DOWN_DECAY_DAYS,\n"
        "  'DROP_DOWN_DECAY_STEPS': e.DROP_DOWN_DECAY_STEPS,\n"
        "}))\n"
    )
    # Passed as a single argv element rather than through a shell, so the newlines
    # in the script survive: `sh -lc "python -c ..."` delivers them as literal
    # backslash-n and python then refuses the source.
    out = subprocess.run(
        ["docker", "exec", "-w", "/app", DOCKER_ENGINE, "python", "-c", script],
        capture_output=True, text=True, timeout=60,
    )
    for line in reversed(out.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    raise PreflightError(f"could not read the engine's scoring settings: {out.stderr}")


# --- the throwaway realm ---------------------------------------------------


def _strip_internal_ids(node):
    """Drop every internal id so Keycloak mints new ones.

    The export carries 175 `id` and `containerId` values belonging to the realm it was
    taken from: clients, roles, groups, client scopes, components. Those are unique
    across the whole Keycloak instance, so importing a copy while the original exists
    fails with a bare "Duplicate resource error" that names nothing. Cross-references
    inside the export are by alias or name rather than by id, so removing them is safe.
    """
    if isinstance(node, dict):
        return {
            k: _strip_internal_ids(v)
            for k, v in node.items()
            if k not in ("id", "containerId")
        }
    if isinstance(node, list):
        return [_strip_internal_ids(v) for v in node]
    return node


def _realm_representation(realm_name: str) -> dict:
    """The shipped realm, renamed, with anything run-specific adjusted."""
    rep = _strip_internal_ids(json.loads(REALM_EXPORT.read_text()))
    rep["realm"] = realm_name
    rep["enabled"] = True
    # Public IPs are used to drive the geo rows, and Keycloak refuses plaintext HTTP
    # from a public client address when sslRequired is "external".
    rep["sslRequired"] = "none"
    # The export's frontend URL points at the shared realm's issuer. Leaving it set
    # would make tokens claim the wrong realm.
    rep.get("attributes", {}).pop("frontendUrl", None)
    return rep


def engine_token(realm_name: str) -> str:
    """A client-credentials token for the engine's API, from the run's own realm."""
    secret = _client_secret(realm_name, "adaptive-auth-api")
    r = requests.post(
        f"{KC_BASE}/realms/{realm_name}/protocol/openid-connect/token",
        data={
            "client_id": "adaptive-auth-api",
            "client_secret": secret,
            "grant_type": "client_credentials",
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _client_secret(realm_name: str, client_id: str) -> str:
    token = admin_token()
    r = requests.get(
        f"{KC_BASE}/admin/realms/{realm_name}/clients",
        headers={"Authorization": f"Bearer {token}"},
        params={"clientId": client_id}, timeout=20,
    )
    r.raise_for_status()
    uid = r.json()[0]["id"]
    r = requests.get(
        f"{KC_BASE}/admin/realms/{realm_name}/clients/{uid}/client-secret",
        headers={"Authorization": f"Bearer {token}"}, timeout=20,
    )
    r.raise_for_status()
    return r.json()["value"]


def create_run_realm(mode: str = DEFAULT_SCORING_MODE,
                     overrides: dict | None = None,
                     write_params: bool = True) -> str:
    """Import a fresh realm for this run and give it the matrix parameters."""
    realm_name = f"amfa-e2e-{uuid.uuid4().hex[:8]}"
    token = admin_token()

    r = requests.post(
        f"{KC_BASE}/admin/realms",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(_realm_representation(realm_name)),
        timeout=90,
    )
    if r.status_code not in (201, 204):
        raise PreflightError(
            f"could not create the run realm ({r.status_code}): {r.text[:400]}"
        )

    # Anything after the realm exists must clean up on failure, or a run that dies
    # between creating the realm and configuring it leaks a realm that the next run
    # then has to reason about. Observed: the parameter write rejected a payload and
    # the realm survived the traceback.
    try:
        # write_params False leaves the realm with no parameters of its own, which is
        # how a realm looks before anyone configures it. Worth being able to build.
        if write_params:
            _write_params(realm_name, overrides)
        _write_scoring(realm_name, mode)
    except Exception:
        delete_run_realm(realm_name)
        raise
    return realm_name


def _write_params(realm_name: str, overrides: dict | None = None) -> None:
    """Activate the matrix parameter set for the run realm, via the engine's API."""
    token = engine_token(realm_name)
    r = requests.put(
        f"{ENGINE_BASE}/{realm_name}/settings",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(matrix_params(realm_id=realm_name, overrides=overrides)),
        timeout=60,
    )
    if r.status_code not in (200, 201, 204):
        raise PreflightError(
            f"could not write matrix parameters for {realm_name} "
            f"({r.status_code}): {r.text[:400]}"
        )


def _write_scoring(realm_name: str, mode: str = DEFAULT_SCORING_MODE) -> None:
    """Pin the scoring mode. Must run after _write_params, which replaces __meta."""
    token = engine_token(realm_name)
    r = requests.put(
        f"{ENGINE_BASE}/{realm_name}/scoring",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(scoring_config(mode)),
        timeout=60,
    )
    if r.status_code not in (200, 201, 204):
        raise PreflightError(
            f"could not pin scoring mode for {realm_name} "
            f"({r.status_code}): {r.text[:400]}"
        )


def resolved_scoring_mode(realm_name: str) -> str:
    """What the engine will actually use for this realm, read back not assumed."""
    token = engine_token(realm_name)
    r = requests.get(
        f"{ENGINE_BASE}/{realm_name}/scoring",
        headers={"Authorization": f"Bearer {token}"}, timeout=30,
    )
    r.raise_for_status()
    body = r.json()
    return (body or {}).get("mode") or "(engine default)"


def delete_run_realm(realm_name: str, user_ids=None) -> dict:
    """Remove the realm and the engine rows the run produced.

    Deleting the realm removes its users from Keycloak but not the engine's own
    history, which is keyed by user id and would otherwise accumulate on every run.
    Children first, because auth_event references auth_process.
    """
    removed = {}
    ids = [u for u in (user_ids or []) if u]
    if ids:
        quoted = ",".join(f"'{u}'" for u in ids)
        removed["auth_event"] = psql(
            f"delete from auth_event where auth_process in "
            f"(select id from auth_process where user_id in ({quoted}));"
        )
        removed["auth_process"] = psql(
            f"delete from auth_process where user_id in ({quoted});"
        )

    removed["decision_params_config"] = psql(
        f"delete from decision_params_config where realm_id = '{realm_name}';"
    )

    token = admin_token()
    r = requests.delete(
        f"{KC_BASE}/admin/realms/{realm_name}",
        headers={"Authorization": f"Bearer {token}"}, timeout=60,
    )
    removed["realm"] = f"HTTP {r.status_code}"
    return removed


class MatrixRun:
    """Preflight, a throwaway realm, and guaranteed teardown.

    Users created during the run are registered with ``track`` so their engine-side
    history can be removed as well. Teardown runs even when a row raises, because a
    failed run that leaves a realm behind makes the next one ambiguous.
    """

    def __init__(self, skip_preflight: bool = False,
                 mode: str = DEFAULT_SCORING_MODE,
                 overrides: dict | None = None,
                 write_params: bool = True):
        self.skip_preflight = skip_preflight
        self.mode = mode
        self.overrides = overrides
        self.write_params = write_params
        self.realm = None
        self.observed = {}
        self.user_ids: list[str] = []
        self.teardown_report: dict = {}

    def track(self, user_id: str) -> str:
        self.user_ids.append(user_id)
        return user_id

    def __enter__(self):
        if not self.skip_preflight:
            self.observed = preflight()
        self.observed["config_fingerprint"] = config_fingerprint(
            self.mode, self.overrides
        )
        self.realm = create_run_realm(self.mode, self.overrides, self.write_params)
        _LIVE_REALMS.add(self.realm)
        self.observed["realm"] = self.realm
        self.observed["scoring_mode"] = resolved_scoring_mode(self.realm)
        return self

    def __exit__(self, *exc):
        if self.realm:
            _LIVE_REALMS.discard(self.realm)
            self.teardown_report = delete_run_realm(self.realm, self.user_ids)
        return False


def verify_ip_palette(palette: dict) -> dict:
    """Assert every address the matrix uses still resolves to the country it expects.

    DB-IP Lite refreshes monthly and an address can be reassigned between releases. A
    moved country would otherwise surface as a wrong risk level on an unrelated-looking
    row, so it is caught here where the message can say what actually happened.
    """
    script = (
        "import asyncio, json\n"
        "from src.utils.info_provider.geoloc import get_cached_geo_info\n"
        "from src.utils.info_provider.vpn import get_cached_vpn_info\n"
        "async def main():\n"
        "    out = {}\n"
        f"    for ip in {sorted(palette)!r}:\n"
        "        geo = await get_cached_geo_info(ip)\n"
        "        anon = await get_cached_vpn_info(ip)\n"
        "        out[ip] = {'country': geo['country_name'], 'city': geo['city_name'],\n"
        "                   'is_vpn': anon['is_vpn'], 'labels': anon['anon_labels']}\n"
        "    print(json.dumps(out))\n"
        "asyncio.run(main())\n"
    )
    out = subprocess.run(
        ["docker", "exec", "-w", "/app", DOCKER_ENGINE, "python", "-c", script],
        capture_output=True, text=True, timeout=120,
    )
    resolved = None
    for line in reversed(out.stdout.strip().splitlines()):
        try:
            resolved = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    if resolved is None:
        raise PreflightError(f"could not resolve the IP palette: {out.stderr[:400]}")

    moved = [
        f"{ip} resolves to {resolved[ip]['country']!r}, the matrix expects "
        f"{spec['country']!r} ({spec['note']})"
        for ip, spec in palette.items()
        if resolved[ip]["country"] != spec["country"]
    ]
    if moved:
        raise PreflightError(
            "the bundled IP data no longer matches the matrix palette:\n\n  - "
            + "\n\n  - ".join(moved)
            + "\n\nPick replacement addresses, or regenerate the baseline if the "
              "new mapping is acceptable."
        )
    return resolved


# Realms belonging to MatrixRun contexts that are currently open. The sweep must skip
# these: it deletes anything matching the run-realm prefix, which is right for a realm
# abandoned by a dead run and catastrophic for one a live run is still using. Two
# fixtures holding a realm each is enough to hit it, and the second one's preflight
# deleted the first one's realm out from under it, which surfaced as a 404 creating a
# user in a realm that had existed moments earlier.
_LIVE_REALMS: set = set()


def sweep_orphan_realms() -> list:
    """Delete realms left behind by a run that died before its teardown.

    A leaked realm is harmless to the engine but makes the next run ambiguous: an
    operator looking at Keycloak cannot tell which realm belongs to what. Swept at
    preflight rather than at exit, because the run that leaked one is by definition
    the run that did not reach its own cleanup.

    Realms held by a live MatrixRun are skipped. Without that, a session holding two
    of them destroys itself: the second run's preflight deletes the first run's realm,
    and the first run's next login fails with a 404 against a realm that existed a
    moment ago.
    """
    token = admin_token()
    r = requests.get(
        f"{KC_BASE}/admin/realms",
        headers={"Authorization": f"Bearer {token}"}, timeout=30,
    )
    r.raise_for_status()
    stale = [
        realm["realm"] for realm in r.json()
        if realm.get("realm", "").startswith("amfa-e2e-")
        and realm.get("realm") not in _LIVE_REALMS
    ]
    for name in stale:
        requests.delete(
            f"{KC_BASE}/admin/realms/{name}",
            headers={"Authorization": f"Bearer {token}"}, timeout=60,
        )
        psql(f"delete from decision_params_config where realm_id = '{name}';")
    return stale

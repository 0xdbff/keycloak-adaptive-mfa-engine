"""The engine's public API: what it accepts, what it refuses, and how it fails.

The V family of tests/e2e/coverage-plan.md.

`/decision` is the endpoint that decides whether a user is challenged. Everything else
in the suite drives it through a login, which only ever sends well-formed requests from
a trusted caller. These go at it directly, because the interesting cases are the ones a
login cannot produce: a malformed body, a token from the wrong realm, a user with no
history, a request the engine accepts and then cannot store.

Two properties matter more than the status codes.

**Bad input must not become a risk decision.** A request the engine cannot understand
has to be refused, not scored, because a scored request returns a level and a level
decides whether someone is challenged.

**Failing should not mean failing open.** When the engine cannot complete an evaluation
it must fail, not fabricate a verdict: a request it accepts and then cannot store
comes back as an error, never as HTTP 200 with a riskLevel. Returning "the configured
fallback" instead of an error on such a failure -- treating the environment as
authoritative for that value -- would carry a real cost: a malformed field would be
enough to make a real Risk 4 (deny) verdict come back as Risk 1 (no challenge),
indistinguishable from a real decision to anything checking only the status code. See
`test_a_request_the_engine_cannot_store_fails_rather_than_fabricating_a_verdict`, which
is the reason this file exists.

Runs from the host against a live stack; needs only `requests`.
"""

import uuid

import pytest
import requests

from tests.e2e import e2e_common as c

TIMEOUT = 20


@pytest.fixture(scope="module")
def token() -> str:
    """A service-account token for the engine, as the SPI would obtain."""
    return c.engine_sa_token()


@pytest.fixture(scope="module")
def base_context() -> dict:
    """The fields every request carries, for a user with no history."""
    return {
        "user_id": str(uuid.uuid4()),
        "client": c.TEST_CLIENT,
        "ip_address": "212.51.144.1",
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
        ),
        "system_language": "en-US",
        "screen_resolution": "1728x1117",
        "realm_id": c.REALM,
        "group_id": "default",
    }


def post_decision(token: str, body: dict, bearer: str | None = None):
    headers = {}
    auth = token if bearer is None else bearer
    if auth is not None:
        headers["Authorization"] = f"Bearer {auth}"
    return requests.post(
        f"{c.ENGINE_BASE}/decision", json=body, headers=headers, timeout=TIMEOUT
    )


def register_context(token: str, context: dict) -> str:
    """Register a context and return its hash, the way the SPI does before deciding."""
    r = requests.post(
        f"{c.ENGINE_BASE}/auth_context",
        json=context,
        headers={"Authorization": f"Bearer {token}"},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["hash"]


def decision_body(token: str, context: dict) -> dict:
    return {
        **context,
        "event_id": str(uuid.uuid4()),
        "auth_context_hash": register_context(token, context),
    }


# --- V01: malformed input is refused, not scored --------------------------

# `replace` swaps the whole body; `override` edits one field of a valid one. Both are
# needed: a truncated body and a well-formed body with one bad field fail differently.
MALFORMED = [
    pytest.param({}, None, "an empty body", id="empty-body"),
    pytest.param({"realm_id": c.REALM}, None, "a body with only one field", id="one-field"),
    pytest.param(None, {"ip_address": "999.999.999.999"}, "an impossible address", id="bad-ip"),
    pytest.param(None, {"ip_address": "not-an-address"}, "a non-address string", id="not-an-ip"),
    pytest.param(None, {"client": {"nested": {"deeper": [1] * 50}}}, "a nested object where a string belongs", id="nested-object"),
    pytest.param(None, {"user_agent": None}, "a null in a required field", id="null-field"),
    pytest.param(
        None, {"screen_resolution": "abc"}, "a non-numeric screen resolution",
        id="non-numeric-screen-resolution",
    ),
    pytest.param(
        None, {"screen_resolution": ""}, "an empty screen resolution",
        id="empty-screen-resolution",
    ),
]
# Deliberately not here: an event id that is not a uuid. It is accepted rather than
# refused, and answered with a risk level, so it belongs with the fail-open cases below.


@pytest.mark.parametrize("replace,override,description", MALFORMED)
def test_a_malformed_decision_request_is_refused_rather_than_scored(
    token, base_context, replace, override, description
):
    """V01. A request the engine cannot understand must not produce a risk level.

    Parametrized rather than one test with seven asserts, so a single newly-accepted
    shape is named in the failure instead of hiding behind the first one.
    """
    body = replace if replace is not None else {
        **decision_body(token, base_context), **override
    }

    response = post_decision(token, body)

    assert response.status_code == 422, (
        f"the engine answered {description} with HTTP {response.status_code} "
        f"instead of refusing it: {response.text[:300]}"
    )
    assert "riskLevel" not in response.text, (
        f"the engine returned a risk level for {description}, so unusable input "
        f"produced a decision about whether to challenge a user: {response.text[:300]}"
    )


def test_a_decision_request_without_a_screen_resolution_is_scored(token, base_context):
    """V01. A login that has no screen resolution, such as a direct grant, is not
    malformed. The SPI sends the field as null and, when /auth_context failed, no
    auth context hash; the login must still get a risk level, not a 422 that leaves
    Keycloak on the realm's fallback risk."""
    body = {
        **base_context,
        "event_id": str(uuid.uuid4()),
        "screen_resolution": None,
    }

    response = post_decision(token, body)

    assert response.status_code == 200, (
        f"a decision request without a screen resolution was answered "
        f"HTTP {response.status_code} instead of scored: {response.text[:300]}"
    )
    assert "riskLevel" in response.json(), response.text[:300]


# --- V02: authentication ---------------------------------------------------


@pytest.mark.parametrize(
    "bearer,expected_status,expected_detail",
    [
        pytest.param("", 401, "Missing bearer token", id="no-token"),
        pytest.param("not.a.token", 401, "Malformed token", id="garbage-token"),
        # A structurally valid JWT signed with nothing the engine trusts. Rejected at
        # the issuer check, before signature verification, hence 403 rather than 401.
        pytest.param(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln", 403, "issuer",
            id="untrusted-token",
        ),
    ],
)
def test_a_decision_requires_a_valid_token(
    token, base_context, bearer, expected_status, expected_detail
):
    """V02. The endpoint that decides whether to challenge a user is not public."""
    body = decision_body(token, base_context)

    response = post_decision(token, body, bearer=bearer)

    assert response.status_code == expected_status, (
        f"a request with {bearer!r} as its token was answered "
        f"HTTP {response.status_code}, expected {expected_status}: "
        f"{response.text[:200]}"
    )
    assert expected_detail.lower() in response.text.lower()


def test_a_token_from_one_realm_cannot_score_a_login_in_another(token, base_context):
    """V03. Tenant isolation, which the whole per-realm model rests on.

    Without this, a service account in any realm could ask for decisions about users in
    every other realm, and per-realm parameters would be a preference rather than a
    boundary.
    """
    body = {**decision_body(token, base_context), "realm_id": "master"}

    response = post_decision(token, body)

    assert response.status_code == 403, (
        f"a token issued for realm {c.REALM!r} was allowed to request a decision for "
        f"realm 'master' (HTTP {response.status_code}): {response.text[:200]}"
    )


# --- V04: a user the engine has never seen --------------------------------


def test_a_user_with_no_history_is_scored_cautiously(token, base_context):
    """V04. The cold-start path, which every real user takes exactly once.

    The engine cannot know anything about a brand-new user, so the only safe answer is
    a cautious one. Asserted as a floor rather than an exact level, because the exact
    level is the history gate's business and is covered by the matrix's G rows.
    """
    body = decision_body(token, {**base_context, "user_id": str(uuid.uuid4())})

    response = post_decision(token, body)

    assert response.status_code == 200, response.text[:300]
    risk = response.json()["riskLevel"]
    assert risk >= 3, (
        f"a user the engine has never seen was scored Risk {risk}, which is not a "
        f"step-up. An unknown user is the one case where nothing is known, so a "
        f"permissive answer means an attacker's first login is the unchallenged one."
    )


# --- V05: an unstorable request must fail, not fabricate a verdict --------


def unprocessable(kind: str, token: str, context: dict) -> requests.Response:
    """Send a request the engine accepts but cannot store, and return the response.

    Two routes reach the same place, both measured rather than theorised:

    `replay` resubmits an identical body. The second insert violates auth_process_pkey
    on the event id. The SPI mints a fresh id per authentication so a browser cannot do
    this, but a retry can: the request is not idempotent, and a client that resends
    after a timeout resends the same id.

    `malformed-id` sends an event id that is not a uuid. The schema declares
    `event_id: str` while its own docstring says UUID and the column is UUID, so it
    passes validation and fails at the insert.

    Returns the response for the request that fails to store (the second post for
    `replay`, the only post for `malformed-id`).
    """
    if kind == "replay":
        body = decision_body(token, context)
        first = post_decision(token, body)
        assert first.status_code == 200, first.text[:300]
        return post_decision(token, body)

    body = {**decision_body(token, context), "event_id": "not-a-uuid-at-all"}
    return post_decision(token, body)


FAIL_CLOSED_ROUTES = [
    pytest.param("replay", id="resubmitted-request"),
    pytest.param("malformed-id", id="event-id-that-is-not-a-uuid"),
]


@pytest.mark.parametrize("kind", FAIL_CLOSED_ROUTES)
def test_a_request_the_engine_cannot_store_fails_rather_than_fabricating_a_verdict(
    token, base_context, kind
):
    """V05. When evaluation fails, the engine says so instead of answering.

    This suite used to read the environment's `FALLBACK_RISK_LEVEL` and assert the
    response matched it: "fail should still mean a verdict, just a configured one."
    That was a deliberate design decision, made after an earlier xfail argued a failed
    evaluation should not return the lowest risk. Testing exposed the actual cost
    of it: a malformed field made a real Risk 4 (deny) verdict come back as Risk 1 (no
    challenge) instead, because the exception handler converted every unhandled error
    into a fixed, permissive HTTP 200 -- indistinguishable from a genuine decision to
    anything checking only the status code.

    The contract is now the opposite: a request the engine accepts but cannot store
    must come back as a server error, never as HTTP 200 with a riskLevel. Keycloak's
    SPI already treats any non-2xx response from this endpoint as a failure and
    applies its own separately configured fallback (`AdaptiveAuthService` throws on
    status >= 300), so this hands the failure to the layer that was always meant to
    own it, instead of masking it as a low-risk success.

    Two routes reach this path, both measured. Resubmitting an identical body violates
    `auth_process_pkey` on the event id; the SPI mints a fresh id per authentication so
    a browser cannot do it, but a retry can, since the request is not idempotent. And
    an event id that is not a uuid passes validation, because `DecisionRequest`
    declares `event_id` as `str` while its own docstring and the column both say UUID,
    then fails at the insert.
    """
    response = unprocessable(kind, token, {**base_context, "user_id": str(uuid.uuid4())})

    assert response.status_code >= 500, (
        f"a request the engine could not store was answered HTTP "
        f"{response.status_code}, expected a server error: {response.text[:300]}"
    )
    assert "riskLevel" not in response.text, (
        f"a failed evaluation still returned a riskLevel, so it cannot be told "
        f"apart from a real decision: {response.text[:300]}"
    )


def test_a_healthy_request_is_still_scored_normally_after_the_fix(token, base_context):
    """V05b. The companion to the above: only the unstorable path should fail.

    Asserting only "the failed path errors" would still pass if the fix had made
    DecisionService fail closed on every request, healthy ones included. This checks
    a request the engine CAN store is still scored on its merits and returns HTTP 200
    with a riskLevel, so the fix narrows the failure mode rather than widening it.
    """
    healthy = post_decision(
        token, decision_body(token, {**base_context, "user_id": str(uuid.uuid4())})
    )
    assert healthy.status_code == 200, healthy.text[:200]
    assert "riskLevel" in healthy.json(), (
        f"a request the engine could store was not answered with a riskLevel: "
        f"{healthy.text[:200]}"
    )


# --- /health vs /health/detail: liveness vs diagnostic detail --------------
#
# Live, permanent regression coverage for the /health split -- a manual curl
# check against the real stack isn't enough to catch a future regression that
# reintroduces the leak or breaks the authenticated path.

_LEAKY_KEYS = ("geo", "anonymiser", "notes", "egress", "path", "age_days", "labels")


def test_unauthenticated_health_carries_no_diagnostic_detail():
    """Plain /health, reachable by anyone (Docker/orchestrator probes, the e2e
    preflight check), must never carry more than a summary word for ip_data --
    no filesystem paths, database ages, detection-category labels, or hosting
    ASN counts. Confirmed against the real, running engine, not a mock."""
    response = requests.get(f"{c.ENGINE_BASE}/health", timeout=TIMEOUT)
    assert response.status_code in (200, 503), response.text[:200]

    payload = response.json()
    assert set(payload["ip_data"].keys()) == {"status"}, (
        f"unauthenticated /health leaked extra ip_data fields: {payload['ip_data']}"
    )
    body_text = response.text.lower()
    for leaky_key in _LEAKY_KEYS:
        assert leaky_key not in body_text, (
            f"unauthenticated /health response contains {leaky_key!r}: {response.text}"
        )
    assert "/opt/amfa" not in response.text, (
        f"unauthenticated /health leaked an absolute filesystem path: {response.text}"
    )


@pytest.mark.parametrize(
    "bearer,expected_status",
    [
        pytest.param("", 401, id="no-token"),
        pytest.param("not.a.token", 401, id="garbage-token"),
        pytest.param(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln", 403, id="untrusted-token"
        ),
    ],
)
def test_health_detail_rejects_the_same_bad_tokens_decision_does(bearer, expected_status):
    """The full diagnostic inventory must be exactly as protected as /decision --
    reusing the identical require_auth dependency means it should reject the same
    malformed/untrusted tokens the same way, not just an absent one."""
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    response = requests.get(
        f"{c.ENGINE_BASE}/health/detail", headers=headers, timeout=TIMEOUT
    )
    assert response.status_code == expected_status, (
        f"a request with {bearer!r} as its token was answered "
        f"HTTP {response.status_code}, expected {expected_status}: "
        f"{response.text[:200]}"
    )


def test_health_detail_with_a_tampered_signature_is_rejected():
    """A real, otherwise-valid token whose signature has been altered must be
    rejected -- proves the check verifies the signature, not just the issuer
    claim's shape."""
    real_token = c.engine_sa_token()
    header, payload, sig = real_token.split(".")
    bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered = f"{header}.{payload}.{bad_sig}"

    response = requests.get(
        f"{c.ENGINE_BASE}/health/detail",
        headers={"Authorization": f"Bearer {tampered}"},
        timeout=TIMEOUT,
    )
    assert response.status_code == 403, response.text[:200]


def test_health_detail_with_a_valid_token_returns_the_full_inventory():
    """The companion to every rejection test above: a genuinely valid token
    must still get the full detail this endpoint exists to provide -- the fix
    gates the leak, it does not remove the diagnostic capability."""
    real_token = c.engine_sa_token()

    response = requests.get(
        f"{c.ENGINE_BASE}/health/detail",
        headers={"Authorization": f"Bearer {real_token}"},
        timeout=TIMEOUT,
    )
    assert response.status_code in (200, 503), response.text[:200]

    payload = response.json()
    assert "geo" in payload["ip_data"], (
        f"an authenticated /health/detail request did not receive the full "
        f"inventory: {payload}"
    )
    assert "anonymiser" in payload["ip_data"]

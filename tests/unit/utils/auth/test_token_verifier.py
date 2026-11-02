import json
import threading
import time
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.exceptions import PyJWKClientError, PyJWKClientConnectionError

import src.utils.auth.token_verifier as tv

# The autouse fixture below stubs _jwks_client out; keep the real one for the
# tests that exercise it directly.
_real_jwks_client = tv._jwks_client

BASE = "https://kc.test/auth"
ISSUER = "https://kc.test/auth/realms/testrealm"

@pytest.fixture
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key

@pytest.fixture(autouse=True)
def patch_jwks(monkeypatch, keypair):
    class _Key:  # mimics PyJWK
        key = keypair.public_key()
    class _Client:
        def get_signing_key_from_jwt(self, token):
            return _Key()
    monkeypatch.setattr(tv, "_jwks_client", lambda issuer: _Client())
    monkeypatch.setattr(tv, "OIDC_TRUSTED_BASE_URLS", [BASE])
    monkeypatch.setattr(tv, "OIDC_VERIFY_AUDIENCE", False)
    monkeypatch.setattr(tv, "OIDC_EXPECTED_AUDIENCE", "amfa")
    monkeypatch.setattr(tv, "OIDC_CLOCK_SKEW_LEEWAY", 30)
    monkeypatch.setattr(tv, "OIDC_CA_BUNDLE", None)
    tv._key_cache.clear()  # isolate stale-cache state between tests
    tv._discovery_failures.clear()  # isolate negative-cache state between tests
    tv._discovery_unreachable.clear()
    tv._discovery_attempt_times.clear()  # isolate rate-limiter state between tests
    tv._discovery_inflight.clear()  # isolate single-flight state between tests
    monkeypatch.setattr(tv, "_discovery_waiters", 0)

def _token(keypair, **overrides):
    claims = {"iss": ISSUER, "sub": "user-1", "azp": "amfa-client",
              "aud": "amfa", "exp": int(time.time()) + 300,
              "realm_access": {"roles": ["amfa-caller"]}}
    claims.update(overrides)
    return jwt.encode(claims, keypair, algorithm="RS256", headers={"kid": "test-kid"})

def test_valid_token_returns_principal(keypair):
    p = tv.verify_token(_token(keypair))
    assert p.issuer == ISSUER
    assert p.realm == "testrealm"
    assert p.client_id == "amfa-client"
    assert "amfa-caller" in p.roles

def test_untrusted_issuer_rejected(keypair):
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair, iss="https://evil.test/auth/realms/x"))
    assert e.value.status_code == 403

def test_any_realm_under_trusted_base_accepted(keypair):
    # A DIFFERENT realm under the same Keycloak base must work with NO config change.
    other = "https://kc.test/auth/realms/brand-new-realm"
    p = tv.verify_token(_token(keypair, iss=other))
    assert p.realm == "brand-new-realm"

def test_lookalike_host_suffix_rejected(keypair):
    # Prefix-style bypass attempt: trusted host as a prefix of an attacker domain.
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair, iss="https://kc.test.evil.com/auth/realms/x"))
    assert e.value.status_code == 403

def test_userinfo_host_spoof_rejected(keypair):
    # `user@host` trick: real host is evil.com, not kc.test.
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair, iss="https://kc.test@evil.com/auth/realms/x"))
    assert e.value.status_code == 403

def test_wrong_scheme_rejected(keypair):
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair, iss="http://kc.test/auth/realms/testrealm"))
    assert e.value.status_code == 403

def test_wrong_path_prefix_rejected(keypair):
    # Right host, but not under the trusted base path (no /auth) or not a realm path.
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair, iss="https://kc.test/realms/testrealm"))
    assert e.value.status_code == 403

def test_expired_token_rejected(keypair):
    # Offset must exceed OIDC_CLOCK_SKEW_LEEWAY (30s, patched above) or PyJWT's
    # leeway tolerance masks the expiry and the token is accepted.
    with pytest.raises(tv.AuthError):
        tv.verify_token(_token(keypair, exp=int(time.time()) - 3600))

def test_tampered_signature_rejected(keypair):
    header, payload, sig = _token(keypair).split(".")
    # Corrupt the FIRST signature char (6 significant base64url bits, unlike the last
    # char which has ignored padding bits and could be a no-op), guaranteeing a real change.
    bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(tv.AuthError):
        tv.verify_token(f"{header}.{payload}.{bad_sig}")

def test_no_issuer_rejected(keypair):
    tok = jwt.encode({"sub": "x", "exp": int(time.time()) + 300}, keypair, algorithm="RS256")
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(tok)
    assert e.value.status_code == 403

def test_audience_enforced_when_enabled(keypair, monkeypatch):
    monkeypatch.setattr(tv, "OIDC_VERIFY_AUDIENCE", True)
    with pytest.raises(tv.AuthError):
        tv.verify_token(_token(keypair, aud="someone-else"))


def _token_no_aud(keypair, **overrides):
    claims = {"iss": ISSUER, "sub": "user-1", "azp": "c",
              "exp": int(time.time()) + 300, "realm_access": {"roles": []}}
    claims.update(overrides)
    return jwt.encode(claims, keypair, algorithm="RS256", headers={"kid": "test-kid"})

def test_verify_audience_false_accepts_token_without_aud(keypair, monkeypatch):
    # Even with audience enforcement ON globally, an explicit verify_audience=False
    # override accepts a generic realm-signed token that carries NO aud. (No current
    # caller passes this combination — the webhook path now requires its own
    # dedicated audience instead — but the override itself must still work.)
    monkeypatch.setattr(tv, "OIDC_VERIFY_AUDIENCE", True)
    p = tv.verify_token(_token_no_aud(keypair), verify_audience=False)
    assert p.realm == "testrealm"

def test_decision_path_still_requires_aud_when_enabled(keypair, monkeypatch):
    # Default path (bearer / decision) with enforcement ON: a token MISSING aud is rejected.
    monkeypatch.setattr(tv, "OIDC_VERIFY_AUDIENCE", True)
    with pytest.raises(tv.AuthError):
        tv.verify_token(_token_no_aud(keypair))  # no override -> require_aud=True

def test_webhook_path_requires_its_own_dedicated_audience(keypair):
    # The webhook path passes verify_audience=True with expected_audience set to
    # the dedicated webhook audience, independent of OIDC_EXPECTED_AUDIENCE. A
    # token carrying the /decision audience ("amfa") must NOT satisfy it.
    with pytest.raises(tv.AuthError):
        tv.verify_token(
            _token(keypair, aud="amfa"),
            verify_audience=True,
            expected_audience="amfa-webhook-event",
        )

def test_webhook_path_accepts_its_dedicated_audience(keypair):
    p = tv.verify_token(
        _token(keypair, aud="amfa-webhook-event"),
        verify_audience=True,
        expected_audience="amfa-webhook-event",
    )
    assert p.realm == "testrealm"


def _client(keypair, fail_after, exc):
    """JWKS client returning the key `fail_after` times, then raising `exc` (a factory)."""
    pub = keypair.public_key()
    calls = {"n": 0}
    class _Key:
        key = pub
    class _Client:
        def get_signing_key_from_jwt(self, token):
            calls["n"] += 1
            if calls["n"] > fail_after:
                raise exc()
            return _Key()
    return _Client()

def test_stale_cache_fallback_on_connectivity_outage(keypair, monkeypatch):
    # 1st verify caches the key; then JWKS is UNREACHABLE (connectivity) -> stale key used.
    client = _client(keypair, 1, lambda: PyJWKClientConnectionError("keycloak unreachable"))
    monkeypatch.setattr(tv, "_jwks_client", lambda issuer: client)
    tv._key_cache.clear()
    assert tv.verify_token(_token(keypair)).realm == "testrealm"   # fetch ok -> caches
    assert tv.verify_token(_token(keypair)).realm == "testrealm"   # unreachable -> stale ok

def test_no_cached_key_fails_closed_on_connectivity_outage(keypair, monkeypatch):
    # Connectivity failure from the start, nothing cached -> 503, never accept.
    client = _client(keypair, 0, lambda: PyJWKClientConnectionError("unreachable"))
    monkeypatch.setattr(tv, "_jwks_client", lambda issuer: client)
    tv._key_cache.clear()
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair))
    assert e.value.status_code == 503

def test_revoked_key_fails_closed_even_with_cached_key(keypair, monkeypatch):
    # Tests the _key_cache layer: once PyJWKClient reports the kid is gone from a
    # SUCCESSFULLY-fetched JWKS (revocation), it raises PyJWKClientError, and our code
    # must fail closed (403) rather than serve the stale _key_cache entry.
    # NOTE on end-to-end timeliness: PyJWKClient itself caches the JWKS for JWKS_CACHE_TTL,
    # so in production a revoked key can still be accepted until that cache expires — i.e.
    # revocation is bounded by JWKS_CACHE_TTL (300s), not immediate. This test monkeypatches
    # _jwks_client and therefore isolates the fail-closed behavior of our cache layer only.
    client = _client(keypair, 1, lambda: PyJWKClientError("Unable to find matching kid"))
    monkeypatch.setattr(tv, "_jwks_client", lambda issuer: client)
    tv._key_cache.clear()
    assert tv.verify_token(_token(keypair)).realm == "testrealm"   # caches key for kid
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair))                            # kid now gone -> fail closed
    assert e.value.status_code == 403

def test_stale_key_past_ttl_not_used(keypair, monkeypatch):
    # Connectivity outage, but the cached key is older than JWKS_CACHE_TTL -> not used -> 503.
    client = _client(keypair, 1, lambda: PyJWKClientConnectionError("unreachable"))
    monkeypatch.setattr(tv, "_jwks_client", lambda issuer: client)
    monkeypatch.setattr(tv, "JWKS_CACHE_TTL", -1)  # any cached key is immediately "too old"
    tv._key_cache.clear()
    assert tv.verify_token(_token(keypair)).realm == "testrealm"   # caches
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair))                            # stale beyond TTL -> 503
    assert e.value.status_code == 503


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def test_discover_jwks_uri_happy_path(monkeypatch):
    doc = {"issuer": ISSUER, "jwks_uri": "https://kc.test/auth/realms/testrealm/protocol/openid-connect/certs"}
    monkeypatch.setattr(tv.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(doc))
    jwks_uri = tv._discover_jwks_uri(ISSUER)
    assert jwks_uri == doc["jwks_uri"]


def test_ssl_context_none_without_ca_bundle(monkeypatch):
    monkeypatch.setattr(tv, "OIDC_CA_BUNDLE", None)
    assert tv._ssl_context() is None  # system trust store used (public CAs work)


def test_ssl_context_loads_custom_ca(monkeypatch):
    monkeypatch.setattr(tv, "OIDC_CA_BUNDLE", "/etc/ssl/private-ca.pem")
    loaded = {}
    class _Ctx:
        def load_verify_locations(self, cafile=None):
            loaded["cafile"] = cafile
    # verification stays on (create_default_context); we only add the CA
    monkeypatch.setattr(tv.ssl, "create_default_context", lambda: _Ctx())
    ctx = tv._ssl_context()
    assert isinstance(ctx, _Ctx)
    assert loaded["cafile"] == "/etc/ssl/private-ca.pem"


def test_discovery_fetch_receives_ssl_context(monkeypatch):
    doc = {"issuer": ISSUER, "jwks_uri": ISSUER + "/protocol/openid-connect/certs"}
    captured = {}
    def _fake_urlopen(url, timeout=None, context="MISSING"):
        captured["context_passed"] = context  # proves _discover_jwks_uri passes context=
        return _FakeResponse(doc)
    monkeypatch.setattr(tv.urllib.request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(tv, "OIDC_CA_BUNDLE", None)
    tv._discover_jwks_uri(ISSUER)
    assert captured["context_passed"] is None  # None (system trust) when no CA bundle


def test_discover_jwks_uri_issuer_mismatch_rejected(monkeypatch):
    doc = {"issuer": "https://evil.test/auth/realms/x", "jwks_uri": "https://evil.test/certs"}
    monkeypatch.setattr(tv.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(doc))
    with pytest.raises(tv.AuthError) as e:
        tv._discover_jwks_uri(ISSUER)
    assert e.value.status_code == 403


def test_discover_jwks_uri_missing_jwks_uri_rejected(monkeypatch):
    doc = {"issuer": ISSUER}
    monkeypatch.setattr(tv.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(doc))
    with pytest.raises(tv.AuthError) as e:
        tv._discover_jwks_uri(ISSUER)
    assert e.value.status_code == 503


def test_discover_jwks_uri_fetch_failure_rejected(monkeypatch):
    def _raise(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(tv.urllib.request, "urlopen", _raise)
    with pytest.raises(tv.AuthError) as e:
        tv._discover_jwks_uri(ISSUER)
    assert e.value.status_code == 503


# --- Log forgery through the token issuer claim ----------------------------


def test_urlparse_alone_is_fooled_by_embedded_crlf():
    """Characterizes the actual root cause, independent of the fix: urlparse
    silently strips CR/LF while parsing, so _validate_issuer's structural
    comparison ALONE can be satisfied by a value that still carries a raw,
    embedded line break in the original string. This is exactly why the real
    fix lives earlier, in _unverified_issuer -- rejecting the value before it
    is a string that gets used to derive trust from a lossy parse (or before
    it reaches any other consumer), and never in _validate_issuer's parsing
    logic itself."""
    forged = ISSUER + "\r\nFORGED ENTRY user=admin mfa=disabled by=attacker"
    # If this raises, urlparse's CRLF-stripping quirk is no longer present
    # (or was never present in this Python version) and this test -- not the
    # fix -- would need revisiting; it isn't expected to raise today.
    realm = tv._validate_issuer(forged)
    assert "FORGED ENTRY" in realm  # the parsed view swallowed the CRLF


def test_crlf_in_issuer_rejected_before_reaching_validate_issuer(keypair):
    """The end-to-end path must reject a CRLF-bearing issuer even though
    _validate_issuer alone (previous test) would have been fooled by it --
    proving _unverified_issuer's earlier gate is what actually closes this,
    not anything inside _validate_issuer."""
    forged = ISSUER + "\r\nFORGED ENTRY user=admin mfa=disabled by=attacker"
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair, iss=forged))
    assert e.value.status_code == 403


def test_crlf_in_issuer_never_reaches_the_discovery_log(caplog):
    """Defense in depth, exercised directly against the vulnerable function
    rather than through the (now-fixed) earlier gate: even if a CRLF-bearing
    issuer somehow reached _discover_jwks_uri, its own failure-path log call
    must not leak the raw line break. This is the exact live-reproduced
    scenario from the finding -- an unsigned token whose issuer named a
    trusted host, then a line break and fabricated text, produced a
    standalone forged log line when the resulting discovery fetch failed."""
    forged = ISSUER + "\r\nFORGED ENTRY user=admin mfa=disabled by=attacker"
    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(forged)
    for record in caplog.records:
        assert "\r" not in record.getMessage()
        assert "\n" not in record.getMessage()


def test_crlf_in_kid_rejected(keypair):
    """A second, independent injection point: the JWT header's kid, also
    read before any signature check. A trusted, otherwise-ordinary issuer
    plus a CRLF-bearing kid must still be rejected -- this requires no
    urlparse-stripping trick at all, unlike the issuer vector above."""
    header, payload, sig = _token(keypair).split(".")
    forged_header = (
        jwt.utils.base64url_encode(
            json.dumps(
                {"kid": "test-kid\r\nFORGED ENTRY user=admin mfa=disabled by=attacker",
                 "alg": "RS256", "typ": "JWT"}
            ).encode()
        )
    ).decode()
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(f"{forged_header}.{payload}.{sig}")
    assert e.value.status_code == 403


def test_crlf_in_kid_never_reaches_a_log_line(keypair, monkeypatch, caplog):
    """Defense in depth, exercised past the (now-fixed) earlier gate: even if
    a CRLF-bearing kid somehow reached _resolve_signing_key's fail-closed log
    branch (simulating a kid absent from a successfully-fetched JWKS), that
    branch's own sanitization must not leak the raw line break -- including
    the version echoed back through PyJWKClientError's own message text,
    which carries the forged content a SECOND time if unsanitized.

    _reject_unsafe_kid is monkeypatched to a no-op here specifically so this
    test proves the log call's OWN sanitization, not just that the earlier
    gate prevents this kid from ever reaching it -- otherwise this test would
    be vacuous (the gate would reject the token before either log call site
    ever ran, regardless of whether their sanitization was correct, deleted,
    or broken)."""
    monkeypatch.setattr(tv, "_reject_unsafe_kid", lambda kid: None)
    forged_kid = "test-kid\r\nFORGED ENTRY user=admin mfa=disabled by=attacker"

    class _Client:
        def get_signing_key_from_jwt(self, token):
            raise PyJWKClientError(f"Unable to find a signing key that matches: \"{forged_kid}\"")

    monkeypatch.setattr(tv, "_jwks_client", lambda issuer: _Client())
    header, payload, sig = _token(keypair).split(".")
    forged_header = jwt.utils.base64url_encode(
        json.dumps({"kid": forged_kid, "alg": "RS256", "typ": "JWT"}).encode()
    ).decode()

    with pytest.raises(tv.AuthError):
        tv.verify_token(f"{forged_header}.{payload}.{sig}")

    assert caplog.records, "expected the fail-closed log branch to actually run"
    for record in caplog.records:
        assert "\r" not in record.getMessage()
        assert "\n" not in record.getMessage()


def test_non_string_issuer_rejected(keypair):
    """A hand-crafted (not PyJWT-encoded) token can carry any JSON type for
    `iss` -- PyJWT's own encode() refuses a non-string issuer, so this
    builds the token by hand the same way the kid tests above do, to reach
    a code path an attacker who isn't using PyJWT to build their forgery
    could still reach. A non-string iss must be rejected outright rather
    than reaching urlparse (which would raise a less specific/consistent
    error, or in principle behave unexpectedly on a non-string input)."""
    good_token = _token(keypair)
    header, payload_b64, sig = good_token.split(".")
    payload = jwt.decode(good_token, options={"verify_signature": False})
    payload["iss"] = 12345
    forged_payload = jwt.utils.base64url_encode(
        json.dumps(payload).encode()
    ).decode()
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(f"{header}.{forged_payload}.{sig}")
    assert e.value.status_code == 403


def test_sanitize_for_log_replaces_control_characters():
    assert tv._sanitize_for_log("a\r\nb") == "a  b"
    assert tv._sanitize_for_log("a\tb") == "a b"
    assert tv._sanitize_for_log(None) == "None"
    assert tv._sanitize_for_log("plain") == "plain"


def test_control_char_blocklist_covers_splitlines_not_just_crlf():
    """A C0-only blocklist would still let NEL
    (\\x85) or the Unicode LINE/PARAGRAPH SEPARATOR code points through --
    str.splitlines() treats all three as line breaks, so a value carrying
    one of them could still fabricate an extra "line" for any Python-based
    log consumer, even though it wouldn't split the raw log file's bytes the
    way a real CR/LF does."""
    for ch in ("\x85", "\u2028", "\u2029"):
        assert tv._CONTROL_CHAR_RE.search(f"a{ch}b"), repr(ch)
        assert ch not in tv._sanitize_for_log(f"a{ch}b")


def test_nel_in_issuer_rejected(keypair):
    """Same end-to-end rejection as the CRLF issuer tests above, but for the
    C1 control NEL specifically, which the original C0-only blocklist would
    have missed."""
    forged = ISSUER + "\x85FORGED ENTRY user=admin mfa=disabled by=attacker"
    with pytest.raises(tv.AuthError) as e:
        tv.verify_token(_token(keypair, iss=forged))
    assert e.value.status_code == 403


# --- Uncached outbound discovery fetch on every request -------------------


def _counting_failing_urlopen(monkeypatch, calls):
    def _raise(*a, **k):
        calls["n"] += 1
        raise OSError("connection refused")
    monkeypatch.setattr(tv.urllib.request, "urlopen", _raise)


def test_negative_cache_prevents_repeated_attempt_within_ttl(monkeypatch):
    """Five requests naming the same
    nonexistent realm must produce only ONE outbound discovery attempt, not
    five -- the rest are answered from the negative cache."""
    calls = {"n": 0}
    _counting_failing_urlopen(monkeypatch, calls)

    for _ in range(5):
        with pytest.raises(tv.AuthError) as e:
            tv._discover_jwks_uri(ISSUER)
        assert e.value.status_code == 503

    assert calls["n"] == 1, f"expected exactly 1 outbound attempt, got {calls['n']}"


def test_negative_cache_expires_after_ttl(monkeypatch):
    calls = {"n": 0}
    _counting_failing_urlopen(monkeypatch, calls)

    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert calls["n"] == 1

    # Simulate the TTL having elapsed rather than sleeping in the test.
    tv._discovery_failures[ISSUER] = time.time() - (tv.DISCOVERY_FAILURE_CACHE_TTL + 1)

    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert calls["n"] == 2, "expired cache entry must allow a fresh outbound attempt"


def _failing_urlopen(monkeypatch, calls, exc):
    def _raise(*a, **k):
        calls["n"] += 1
        raise exc
    monkeypatch.setattr(tv.urllib.request, "urlopen", _raise)


def _http_error(code):
    return tv.urllib.error.HTTPError(ISSUER, code, "error", {}, None)


def _age_failure(seconds):
    """Pretend the issuer's cached failure happened `seconds` ago."""
    tv._discovery_failures[ISSUER] = time.time() - seconds


@pytest.mark.parametrize("exc", [
    OSError("connection refused"),
    TimeoutError("timed out"),
    tv.urllib.error.URLError(TimeoutError("timed out")),
    _http_error(503),
], ids=["refused", "timeout", "urlerror-timeout", "http-503"])
def test_keycloak_unreachable_is_remembered_only_briefly(monkeypatch, exc):
    """A failure that says Keycloak could not be reached is not something a
    client can cause by naming a fake realm, so it uses the short
    DISCOVERY_UNREACHABLE_CACHE_TTL: the realm recovers within seconds of
    Keycloak coming back instead of answering 503 for the full failure TTL."""
    calls = {"n": 0}
    _failing_urlopen(monkeypatch, calls, exc)

    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert calls["n"] == 1, "a repeat within the short TTL must still be answered locally"

    _age_failure(tv.DISCOVERY_UNREACHABLE_CACHE_TTL + 1)
    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert calls["n"] == 2, "after the short TTL a fresh attempt must be allowed"


@pytest.mark.parametrize("exc", [_http_error(404), _http_error(400), ValueError("not JSON")],
                         ids=["http-404", "http-400", "bad-document"])
def test_a_missing_realm_keeps_the_full_failure_ttl(monkeypatch, exc):
    """A 404 is what Keycloak answers for a realm that does not exist, the
    case the negative cache protects against, so it keeps the long TTL."""
    calls = {"n": 0}
    _failing_urlopen(monkeypatch, calls, exc)

    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    _age_failure(tv.DISCOVERY_UNREACHABLE_CACHE_TTL + 1)
    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert calls["n"] == 1, "still within the full failure TTL"

    _age_failure(tv.DISCOVERY_FAILURE_CACHE_TTL + 1)
    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert calls["n"] == 2


def test_a_missing_realm_after_an_outage_gets_the_full_ttl_again(monkeypatch):
    calls = {"n": 0}
    _failing_urlopen(monkeypatch, calls, OSError("connection refused"))
    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert ISSUER in tv._discovery_unreachable

    _age_failure(tv.DISCOVERY_UNREACHABLE_CACHE_TTL + 1)
    _failing_urlopen(monkeypatch, calls, _http_error(404))
    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert ISSUER not in tv._discovery_unreachable

    _age_failure(tv.DISCOVERY_UNREACHABLE_CACHE_TTL + 1)
    with pytest.raises(tv.AuthError):
        tv._discover_jwks_uri(ISSUER)
    assert calls["n"] == 2, "the 404 must be remembered for the full TTL"


def test_pruning_forgets_the_unreachable_marker(monkeypatch):
    now = time.time()
    tv._discovery_failures["gone"] = now - (tv.DISCOVERY_UNREACHABLE_CACHE_TTL + 1)
    tv._discovery_unreachable.add("gone")
    tv._discovery_failures["recent"] = now
    tv._discovery_unreachable.add("recent")

    tv._prune_discovery_failures(now)

    assert "gone" not in tv._discovery_failures and "gone" not in tv._discovery_unreachable
    assert "recent" in tv._discovery_failures and "recent" in tv._discovery_unreachable


def test_negative_cache_bounded_by_max_size(monkeypatch):
    """A client cycling through distinct fake realm names is otherwise
    unbounded (the realm segment is attacker-chosen) -- the cache itself
    must not grow past DISCOVERY_FAILURE_CACHE_MAX_SIZE even within one TTL
    window, evicting the OLDEST entries first."""
    monkeypatch.setattr(tv, "DISCOVERY_FAILURE_CACHE_MAX_SIZE", 3)
    now = time.time()
    tv._discovery_failures.update({
        "issuer-0": now - 4,
        "issuer-1": now - 3,
        "issuer-2": now - 2,
        "issuer-3": now - 1,
    })

    tv._prune_discovery_failures(now)

    assert len(tv._discovery_failures) == 3
    assert "issuer-0" not in tv._discovery_failures, "oldest entry must be evicted first"
    assert set(tv._discovery_failures) == {"issuer-1", "issuer-2", "issuer-3"}


def test_rate_limiter_caps_total_attempts_across_distinct_issuers(monkeypatch):
    """Closes the variant a per-issuer negative cache alone can't catch: a
    fresh fake realm name on every request is a cache MISS every time, so
    the rate limiter must cap total outbound ATTEMPTS across ALL issuers
    combined, not just repeats of the same one."""
    monkeypatch.setattr(tv, "DISCOVERY_RATE_LIMIT_MAX_ATTEMPTS", 3)
    calls = {"n": 0}
    _counting_failing_urlopen(monkeypatch, calls)

    for i in range(3):
        with pytest.raises(tv.AuthError) as e:
            tv._discover_jwks_uri(f"https://kc.test/auth/realms/fake-{i}")
        assert e.value.status_code == 503

    assert calls["n"] == 3

    # The 4th attempt, against yet another brand-new issuer, must be
    # rejected by the RATE LIMITER (no outbound call made at all) rather
    # than falling through to a real fetch.
    with pytest.raises(tv.AuthError) as e:
        tv._discover_jwks_uri("https://kc.test/auth/realms/fake-3")
    assert e.value.status_code == 503
    assert calls["n"] == 3, "rate-limited attempt must not reach the network"


def test_rate_limiter_resets_after_window_elapses(monkeypatch):
    monkeypatch.setattr(tv, "DISCOVERY_RATE_LIMIT_MAX_ATTEMPTS", 2)
    now = time.time()
    tv._discovery_attempt_times.extend([now - 1, now - 0.5])

    with pytest.raises(tv.AuthError):
        tv._check_discovery_rate_limit(now)  # budget already exhausted

    # Simulate the whole window having elapsed rather than sleeping.
    later = now + tv.DISCOVERY_RATE_LIMIT_WINDOW_SECONDS + 1
    tv._check_discovery_rate_limit(later)  # must not raise: old timestamps pruned


def test_negative_cache_hit_does_not_consume_rate_limit_budget(monkeypatch):
    """Ordering matters: a request answered locally from the negative cache
    is not a real outbound attempt, so it must not spend any of the rate
    limiter's shared budget -- otherwise repeated requests for one already-
    known-bad issuer could starve a genuinely new realm's very first,
    legitimate discovery attempt."""
    monkeypatch.setattr(tv, "DISCOVERY_RATE_LIMIT_MAX_ATTEMPTS", 1)
    tv._discovery_failures[ISSUER] = time.time()  # seed a recent failure

    for _ in range(5):
        with pytest.raises(tv.AuthError) as e:
            tv._discover_jwks_uri(ISSUER)
        assert e.value.status_code == 503

    assert len(tv._discovery_attempt_times) == 0, (
        "negative-cache hits must not consume rate-limit budget"
    )


def test_single_flight_prevents_a_concurrent_flood_from_all_reaching_the_network(monkeypatch):
    """With only the negative cache (no single-flight guard), N genuinely
    concurrent threads racing in for the same brand-new issuer ALL pass the
    cache-miss check before the first one's failure is ever recorded, so all
    N make a real outbound fetch -- measured at 36 of 40 truly-simultaneous
    requests against a single fake realm. This is a real thread-concurrency
    test (not sequential calls) using a deliberately slow fake fetch to hold
    the race window open long enough for every racer to arrive while the
    first request is still in flight."""
    N = 20
    start_barrier = threading.Barrier(N)
    calls = {"n": 0}
    calls_lock = threading.Lock()

    def _slow_raise(*a, **k):
        with calls_lock:
            calls["n"] += 1
        time.sleep(0.2)  # hold the race window open for every racer to arrive
        raise OSError("connection refused")

    monkeypatch.setattr(tv.urllib.request, "urlopen", _slow_raise)

    results = [None] * N

    def _race(i):
        start_barrier.wait()  # release all N threads at (as close as possible to) once
        try:
            tv._discover_jwks_uri(ISSUER)
            results[i] = "success"
        except tv.AuthError as e:
            results[i] = e.status_code

    threads = [threading.Thread(target=_race, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert calls["n"] == 1, (
        f"expected exactly 1 real outbound fetch across {N} concurrent racers, got {calls['n']}"
    )
    assert results == [503] * N, f"every racer must still get a definite 503, got {results}"


def test_single_flight_marker_is_released_after_completion(monkeypatch):
    """The in-flight marker must not leak past one call -- otherwise every
    subsequent request for an issuer would be permanently fail-fast-rejected
    even after the first attempt (successful or not) has finished."""
    doc = {"issuer": ISSUER, "jwks_uri": ISSUER + "/protocol/openid-connect/certs"}
    monkeypatch.setattr(tv.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(doc))

    tv._discover_jwks_uri(ISSUER)  # completes normally

    assert ISSUER not in tv._discovery_inflight, (
        "in-flight marker must be cleared once the call completes"
    )

    # A second, sequential call must not be rejected as "already in flight".
    jwks_uri = tv._discover_jwks_uri(ISSUER)
    assert jwks_uri == doc["jwks_uri"]


def _race_discovery(n, urlopen, monkeypatch):
    """Release n threads at once into _discover_jwks_uri(ISSUER); return each result."""
    start_barrier = threading.Barrier(n)
    monkeypatch.setattr(tv.urllib.request, "urlopen", urlopen)
    results = [None] * n

    def _race(i):
        start_barrier.wait()
        try:
            results[i] = tv._discover_jwks_uri(ISSUER)
        except tv.AuthError as e:
            results[i] = e.status_code

    threads = [threading.Thread(target=_race, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    return results


def _slow_fetch(doc, calls, delay=0.2):
    calls_lock = threading.Lock()

    def _fetch(*a, **k):
        with calls_lock:
            calls["n"] += 1
        time.sleep(delay)  # hold the race window open for every racer to arrive
        return _FakeResponse(doc)

    return _fetch


def test_concurrent_requests_for_a_new_realm_share_one_successful_fetch(monkeypatch):
    """A genuinely NEW, VALID realm hit by several requests at once (the admin
    page loads its settings and scoring config in parallel; a burst of logins
    right after an engine restart) must make exactly ONE outbound fetch, and
    every request must get its result. Turning the others away with a 503,
    the original single-flight behaviour, failed legitimate traffic. None of
    them may be recorded as a discovery failure."""
    N = 20
    monkeypatch.setattr(tv, "DISCOVERY_MAX_WAITERS", N)
    doc = {"issuer": ISSUER, "jwks_uri": ISSUER + "/protocol/openid-connect/certs"}
    calls = {"n": 0}

    results = _race_discovery(N, _slow_fetch(doc, calls), monkeypatch)

    assert calls["n"] == 1, f"expected exactly 1 real fetch across {N} racers, got {calls['n']}"
    assert results == [doc["jwks_uri"]] * N, f"every racer must get the shared result, got {results}"
    assert ISSUER not in tv._discovery_failures
    assert tv._discovery_waiters == 0, "the waiter count must return to zero"
    assert ISSUER not in tv._discovery_inflight


def test_waiters_past_the_cap_still_fail_fast(monkeypatch):
    """Each waiter holds a worker thread, so only DISCOVERY_MAX_WAITERS may
    wait at once; everyone past that gets the immediate 503, with no outbound
    call, exactly as before. A legitimate success must still not be recorded
    as a failure for the ones turned away."""
    N = 20
    monkeypatch.setattr(tv, "DISCOVERY_MAX_WAITERS", 3)
    doc = {"issuer": ISSUER, "jwks_uri": ISSUER + "/protocol/openid-connect/certs"}
    calls = {"n": 0}

    results = _race_discovery(N, _slow_fetch(doc, calls), monkeypatch)

    assert calls["n"] == 1
    winners = [r for r in results if r == doc["jwks_uri"]]
    losers = [r for r in results if r == 503]
    assert len(winners) == 1 + 3, f"expected the fetcher plus 3 waiters to succeed, got {len(winners)}"
    assert len(losers) == N - 4, f"expected {N - 4} fail-fast 503s, got {len(losers)}"
    assert ISSUER not in tv._discovery_failures, (
        "requests turned away by the cap on a SUCCESSFUL fetch must not be recorded as a failure"
    )
    assert tv._discovery_waiters == 0


def test_waiters_get_the_fetchers_error(monkeypatch):
    """A waiter must see the same outcome as the fetch it waited on, including
    a non-503 rejection such as an issuer mismatch."""
    N = 5
    monkeypatch.setattr(tv, "DISCOVERY_MAX_WAITERS", N)
    doc = {"issuer": "https://kc.test/auth/realms/other", "jwks_uri": "https://x/certs"}
    calls = {"n": 0}

    results = _race_discovery(N, _slow_fetch(doc, calls), monkeypatch)

    assert calls["n"] == 1
    assert results == [403] * N, f"every racer must get the mismatch rejection, got {results}"


def test_a_waiter_gives_up_when_the_fetch_outlasts_its_timeout(monkeypatch):
    """A waiter waits at most OIDC_DISCOVERY_TIMEOUT + 1 seconds, then gets a
    503 and releases its slot, even if the fetch it waited on is still running."""
    monkeypatch.setattr(tv, "OIDC_DISCOVERY_TIMEOUT", 0)  # waiter gives up after ~1s
    doc = {"issuer": ISSUER, "jwks_uri": ISSUER + "/protocol/openid-connect/certs"}
    calls = {"n": 0}

    results = _race_discovery(2, _slow_fetch(doc, calls, delay=1.6), monkeypatch)

    assert calls["n"] == 1
    assert sorted(results, key=str) == sorted([doc["jwks_uri"], 503], key=str), results
    assert tv._discovery_waiters == 0, "a waiter that timed out must release its slot"


def test_concurrent_first_requests_share_one_jwks_client(monkeypatch):
    """Threads that shared one discovery fetch must also end up with one stored
    PyJWKClient, so they share one key cache instead of each fetching keys."""
    N = 8
    monkeypatch.setattr(tv, "DISCOVERY_MAX_WAITERS", N)
    monkeypatch.setattr(tv, "_jwks_clients", {})
    doc = {"issuer": ISSUER, "jwks_uri": ISSUER + "/protocol/openid-connect/certs"}
    calls = {"n": 0}
    monkeypatch.setattr(tv.urllib.request, "urlopen", _slow_fetch(doc, calls))
    start_barrier = threading.Barrier(N)
    clients = [None] * N

    def _race(i):
        start_barrier.wait()
        clients[i] = _real_jwks_client(ISSUER)

    threads = [threading.Thread(target=_race, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert calls["n"] == 1
    assert all(c is not None for c in clients)
    assert all(c is tv._jwks_clients[ISSUER] for c in clients), "all racers must use the stored client"

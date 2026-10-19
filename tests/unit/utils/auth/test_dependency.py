import pytest
from fastapi import HTTPException
from starlette.requests import Request

import src.utils.auth.dependency as dep
from src.utils.auth.token_verifier import AuthError, VerifiedPrincipal


def _request(headers: dict) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "headers": raw, "state": {}})


def _principal(realm="testrealm", jti="j1"):
    return VerifiedPrincipal(
        issuer=f"https://kc.test/auth/realms/{realm}", realm=realm,
        client_id="amfa-client", roles=[], audiences=["amfa"],
        subject="u1", claims={"jti": jti, "exp": 9999999999},
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_require_auth_missing_header_401(monkeypatch):
    with pytest.raises(HTTPException) as e:
        await dep.require_auth(_request({}))
    assert e.value.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_require_auth_valid(monkeypatch):
    monkeypatch.setattr(dep, "verify_token", lambda t: _principal())
    req = _request({"Authorization": "Bearer abc"})
    p = await dep.require_auth(req)
    assert p.realm == "testrealm"
    assert req.state.principal.realm == "testrealm"


@pytest.mark.asyncio(loop_scope="session")
async def test_require_auth_maps_autherror(monkeypatch):
    def _raise(_):
        raise AuthError(403, "Untrusted issuer")
    monkeypatch.setattr(dep, "verify_token", _raise)
    with pytest.raises(HTTPException) as e:
        await dep.require_auth(_request({"Authorization": "Bearer abc"}))
    assert e.value.status_code == 403


def test_enforce_tenant_mismatch():
    with pytest.raises(HTTPException) as e:
        dep.enforce_tenant(_principal(realm="a"), "b")
    assert e.value.status_code == 403


def test_enforce_tenant_match():
    dep.enforce_tenant(_principal(realm="a"), "a")  # no raise


@pytest.mark.asyncio(loop_scope="session")
async def test_verify_signed_payload_requires_webhook_audience(monkeypatch):
    captured = {}

    def _fake_verify_token(token, *, verify_audience=None, expected_audience=None):
        captured["verify_audience"] = verify_audience
        captured["expected_audience"] = expected_audience
        return _principal()

    monkeypatch.setattr(dep, "verify_token", _fake_verify_token)
    req = _request({"SignedPayload": "tok"})
    await dep.verify_signed_payload(req, None)

    # Must enforce audience, and specifically the dedicated webhook audience —
    # never OIDC_EXPECTED_AUDIENCE (the /decision one) and never skipped.
    assert captured["verify_audience"] is True
    assert captured["expected_audience"] == dep.WEBHOOK_EXPECTED_AUDIENCE


def test_enforce_webhook_subject_matching_ok():
    dep.enforce_webhook_subject(_principal(), "u1")  # principal's subject is "u1"


def test_enforce_webhook_subject_mismatch_rejected():
    with pytest.raises(HTTPException) as e:
        dep.enforce_webhook_subject(_principal(), "someone-else")
    assert e.value.status_code == 403


def test_enforce_webhook_subject_no_claimed_user_is_noop():
    # No user_id claimed in the event -> nothing to verify identity against.
    dep.enforce_webhook_subject(_principal(), None)


@pytest.mark.asyncio(loop_scope="session")
async def test_replay_first_ok_second_rejected(monkeypatch):
    store = {}
    class _Redis:
        async def set(self, name, value, ex=None, nx=False):
            if nx and name in store:
                return None
            store[name] = value
            return True
    monkeypatch.setattr(dep, "get_redis", lambda: _Redis())
    await dep.enforce_replay_protection(_principal(jti="dup"))
    with pytest.raises(HTTPException) as e:
        await dep.enforce_replay_protection(_principal(jti="dup"))
    assert e.value.status_code == 409


# --- cross-realm monitoring reads ------------------------------------------

_ADMIN_ISSUER = "https://kc.test/auth/realms/master"


def _service_account(issuer=_ADMIN_ISSUER, azp="monitoring-service", client_id_claim="monitoring-service"):
    claims = {"azp": azp}
    if client_id_claim is not None:
        claims["client_id"] = client_id_claim
    return VerifiedPrincipal(
        issuer=issuer, realm=issuer.rsplit("/", 1)[-1], client_id=azp,
        roles=[], audiences=["amfa"], subject="sa", claims=claims,
    )


@pytest.fixture
def trusted_reader(monkeypatch):
    monkeypatch.setattr(
        dep.environment, "MONITORING_TRUSTED_READERS",
        frozenset({(_ADMIN_ISSUER, "monitoring-service")}),
    )


def test_monitoring_read_same_realm_needs_no_trust():
    dep.enforce_monitoring_read(_principal(realm="a"), "a")  # no raise


def test_monitoring_read_cross_realm_refused_by_default():
    with pytest.raises(HTTPException) as e:
        dep.enforce_monitoring_read(_service_account(), "acme")
    assert e.value.status_code == 403


def test_monitoring_read_trusted_service_account_reads_any_realm(trusted_reader):
    dep.enforce_monitoring_read(_service_account(), "acme")  # no raise


def test_monitoring_read_user_signed_in_through_the_trusted_client_refused(trusted_reader):
    # Same azp, but no client_id claim: a person's token, not the service account's.
    with pytest.raises(HTTPException) as e:
        dep.enforce_monitoring_read(_service_account(client_id_claim=None), "acme")
    assert e.value.status_code == 403


def test_monitoring_read_client_id_claim_must_name_the_same_client(trusted_reader):
    with pytest.raises(HTTPException) as e:
        dep.enforce_monitoring_read(_service_account(client_id_claim="other"), "acme")
    assert e.value.status_code == 403


def test_monitoring_read_other_client_in_the_admin_realm_refused(trusted_reader):
    with pytest.raises(HTTPException) as e:
        dep.enforce_monitoring_read(
            _service_account(azp="other-client", client_id_claim="other-client"), "acme"
        )
    assert e.value.status_code == 403


def test_monitoring_read_same_client_on_another_keycloak_refused(trusted_reader):
    with pytest.raises(HTTPException) as e:
        dep.enforce_monitoring_read(
            _service_account(issuer="https://kc-other.test/auth/realms/master"), "acme"
        )
    assert e.value.status_code == 403


def test_monitoring_read_same_client_in_another_realm_refused(trusted_reader):
    # A client of the same name in a tenant realm is not the admin-realm one.
    with pytest.raises(HTTPException) as e:
        dep.enforce_monitoring_read(
            _service_account(issuer="https://kc.test/auth/realms/tenant-a"), "acme"
        )
    assert e.value.status_code == 403


def test_enforce_tenant_ignores_monitoring_trust(trusted_reader):
    # /decision and /settings keep the strict check even for a trusted reader.
    with pytest.raises(HTTPException) as e:
        dep.enforce_tenant(_service_account(), "acme")
    assert e.value.status_code == 403

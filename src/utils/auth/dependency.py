import asyncio
import logging
from time import time

from fastapi import Request, HTTPException

from src.core.redis import get_redis
from src.core.config import environment
from src.core.config.environment import WEBHOOK_REPLAY_TTL, WEBHOOK_EXPECTED_AUDIENCE
from src.utils.auth.token_verifier import verify_token, AuthError, VerifiedPrincipal


def _bearer(request: Request) -> str:
    header = request.headers.get("Authorization")
    if not header or not header.startswith("Bearer "):
        raise AuthError(401, "Missing bearer token")
    return header[len("Bearer "):].strip()


async def require_auth(request: Request) -> VerifiedPrincipal:
    try:
        token = _bearer(request)
        principal = await asyncio.to_thread(verify_token, token)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    request.state.principal = principal
    return principal


async def verify_signed_payload(request: Request, body_token: str | None) -> VerifiedPrincipal:
    token = request.headers.get("SignedPayload") or body_token
    if not token:
        raise HTTPException(status_code=401, detail="Missing signed payload")
    try:
        # Require the dedicated webhook audience (never the /decision one) so an
        # ordinary end-user or unrelated service-account token — signed by a
        # trusted realm but minted for something else — cannot be reshaped into
        # a webhook event just because the signature checks out.
        principal = await asyncio.to_thread(
            verify_token,
            token,
            verify_audience=True,
            expected_audience=WEBHOOK_EXPECTED_AUDIENCE,
        )
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    request.state.principal = principal
    return principal


def enforce_webhook_subject(principal: VerifiedPrincipal, claimed_user_id: str | None) -> None:
    """Reject a webhook event whose claimed subject wasn't who the token was issued to.

    `data.user_id` inside a webhook event is ordinary claim content — a realm
    admin can set it to anything via a protocol mapper. `principal.subject`
    (the token's `sub`) is what Keycloak actually authenticated. Requiring
    them to match stops a token from being reshaped to report an event about
    a different user than the one it was issued for, whether that user is in
    the same realm or (per `enforce_tenant`'s sibling checks elsewhere) another.
    """
    if claimed_user_id is not None and principal.subject != claimed_user_id:
        raise HTTPException(
            status_code=403,
            detail="Event subject does not match the identity the token was issued for",
        )


def enforce_tenant(principal: VerifiedPrincipal, realm_id: str) -> None:
    if principal.realm != realm_id:
        raise HTTPException(status_code=403, detail="Token realm does not match request realm")


def _is_trusted_monitoring_reader(principal: VerifiedPrincipal) -> bool:
    """True when the token is a listed client's own service-account token.

    `azp` alone is not enough: a person who signs in through the same client
    gets a token with that `azp` too. Keycloak adds the `client_id` claim only
    to tokens issued by the client_credentials grant, so requiring it to name
    the same client limits the trust to the service account itself.
    """
    client_id = principal.client_id
    if not client_id or principal.claims.get("client_id") != client_id:
        return False
    return (principal.issuer.rstrip("/"), client_id) in environment.MONITORING_TRUSTED_READERS


def enforce_monitoring_read(principal: VerifiedPrincipal, realm_id: str) -> None:
    """Realm check for the read-only /monitoring endpoints only.

    Same rule as enforce_tenant, except that a service account listed in
    MONITORING_TRUSTED_READERS may read any realm. Never use this on an
    endpoint that writes or decides: those stay on enforce_tenant.
    """
    if principal.realm == realm_id:
        return
    if _is_trusted_monitoring_reader(principal):
        logging.info(
            "Cross-realm monitoring read: client %s from %s read realm %s",
            principal.client_id, principal.issuer, realm_id,
        )
        return
    raise HTTPException(status_code=403, detail="Token realm does not match request realm")


def tenant_scoped_id(realm_id: str, user_id) -> str:
    """Build the `realm:user` fragment every per-user Redis key must use.

    `user_id` alone is not unique across tenants, so any Redis key keyed by
    `user_id` only (a lock, a pending-process pointer, a failure counter) lets
    one realm's caller collide with — and overwrite or read — another realm's
    entry for the same guessed/coincidental id. Always call this with a
    realm_id that came from a verified token (`VerifiedPrincipal.realm`), never
    from unauthenticated request/payload content.
    """
    return f"{realm_id}:{user_id}"


async def enforce_replay_protection(principal: VerifiedPrincipal) -> None:
    jti = principal.claims.get("jti")
    if not jti:
        return
    exp = principal.claims.get("exp")
    ttl = max(1, int(exp - time())) if exp else WEBHOOK_REPLAY_TTL
    redis = get_redis()
    was_set = await redis.set(name=f"webhook_jti:{jti}", value="1", ex=ttl, nx=True)
    if not was_set:
        raise HTTPException(status_code=409, detail="Replayed webhook rejected")


async def require_webhook_auth(request: Request) -> VerifiedPrincipal:
    principal = await verify_signed_payload(request, None)
    await enforce_replay_protection(principal)
    return principal

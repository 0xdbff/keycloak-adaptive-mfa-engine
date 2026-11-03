"""Browser-style login driver for the SSO suite.

Walks test-amfa's test-login client the way a browser would, either through the
"corp" identity provider (SSO) or with a local password, and answers whatever
AMFA asks for on the way: the screen-resolution page, TOTP setup, a TOTP code
or an email code read from Mailpit.

The Keycloak hostname is resolved to 127.0.0.1 inside this process only (see
map_host), so the same URL works here and inside the compose network.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import socket
import struct
import time
import urllib.parse

import requests
import urllib3.util.connection

REDIRECT = "http://127.0.0.1:9/cb"
CLIENT = "test-login"
REALM = "test-amfa"
IDP = "corp"
# A fixed, recognisable device: the checks look for exactly these values in the
# engine's stored history.
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.5 Safari/605.1.15")
SCREEN = "1920x1080"
LANGUAGE = "en-US,en;q=0.9"

_mapped: dict[str, str] = {}
_original_create_connection = urllib3.util.connection.create_connection


def map_host(hostname: str, address: str = "127.0.0.1") -> None:
    """Send connections for hostname to address, for this process only."""
    _mapped[hostname] = address

    def create_connection(addr, *args, **kwargs):
        host, port = addr
        return _original_create_connection((_mapped.get(host, host), port), *args, **kwargs)

    urllib3.util.connection.create_connection = create_connection


def host_resolves(hostname: str) -> bool:
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except OSError:
        return False


def totp_code(secret: str, at: float | None = None) -> str:
    counter = int(at if at is not None else time.time()) // 30
    digest = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1000000:06d}"


def _form_action(page: str, form_id: str) -> str:
    m = re.search(r'<form[^>]*id="%s"[^>]*action="([^"]+)"' % form_id, page) or \
        re.search(r'<form[^>]*action="([^"]+)"[^>]*id="%s"' % form_id, page)
    if not m:
        raise RuntimeError(f"form {form_id!r} has no action on this page")
    return html.unescape(m.group(1))


def _claims(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


class Browser:
    """One browser: cookies persist between logins, so a second login can be silent."""

    def __init__(self, kc_url: str, mailpit_url: str, totp_secrets: dict[str, str]):
        self.kc = kc_url.rstrip("/")
        self.mailpit = mailpit_url.rstrip("/")
        self.totp_secrets = totp_secrets
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": USER_AGENT, "Accept-Language": LANGUAGE})

    def _email_code(self, email: str, timeout: float = 15.0) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            msgs = requests.get(f"{self.mailpit}/api/v1/search", params={"query": f"to:{email}"}, timeout=5).json()
            if msgs.get("messages"):
                body = requests.get(f"{self.mailpit}/api/v1/message/{msgs['messages'][0]['ID']}", timeout=5).json()["Text"]
                code = re.search(r"\b(\d{6})\b", body)
                if code:
                    return code.group(1)
            time.sleep(0.5)
        raise RuntimeError(f"no email code for {email} within {timeout}s")

    def login(self, mode: str, user: str, password: str, email: str,
              silent_only: bool = False, tokens: bool = False) -> dict:
        """Run one login. Returns {"outcome", "steps", ...}.

        outcome is "logged in", "refused" (Keycloak sent the client an error or
        stopped on an error page) or "did not complete".
        silent_only: expect the existing session to log in without any page.
        tokens: redeem the code and report whether AMFA data reached the tokens.
        """
        if not silent_only:
            # So an email code page can only find this login's code.
            requests.delete(f"{self.mailpit}/api/v1/messages", timeout=5)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        url = f"{self.kc}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
            "client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code", "scope": "openid",
            "state": secrets.token_hex(8), "code_challenge": challenge, "code_challenge_method": "S256"})
        steps: list[str] = []
        resp = self.s.get(url, allow_redirects=False)
        for _ in range(30):
            if resp.status_code in (301, 302, 303):
                loc = urllib.parse.urljoin(resp.url, resp.headers["Location"])
                if loc.startswith(REDIRECT):
                    q = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
                    if "code" not in q:
                        steps.append("redirected back with error " + q.get("error", ["?"])[0])
                        return {"outcome": "refused", "steps": steps}
                    steps.append("redirected back with a code")
                    result = {"outcome": "logged in", "steps": steps}
                    if tokens:
                        result["amfa_in_tokens"] = self._amfa_in_tokens(q["code"][0], verifier)
                    return result
                resp = self.s.get(loc, allow_redirects=False)
                continue
            if silent_only:
                steps.append(f"not silent: got a page ({resp.status_code})")
                return {"outcome": "did not complete", "steps": steps}
            page = resp.text
            realm = IDP if f"/realms/{IDP}/" in resp.url else REALM
            if 'name="screenRes"' in page:
                steps.append(f"{realm}: screen-resolution page")
                resp = self.s.post(_form_action(page, "screenResForm"), data={"screenRes": SCREEN}, allow_redirects=False)
                continue
            if 'id="kc-form-login"' in page:
                if realm == REALM and mode == "sso":
                    idp = re.search(r'href="([^"]*/broker/%s/login[^"]*)"' % IDP, page)
                    if not idp:
                        steps.append(f"{realm}: login page has no {IDP} button")
                        break
                    steps.append(f"{realm}: login page, chose {IDP}")
                    resp = self.s.get(urllib.parse.urljoin(resp.url, html.unescape(idp.group(1))), allow_redirects=False)
                    continue
                steps.append(f"{realm}: username and password")
                resp = self.s.post(_form_action(page, "kc-form-login"),
                                   data={"username": user, "password": password, "credentialId": ""},
                                   allow_redirects=False)
                continue
            if 'id="kc-email-code-login-form"' in page:
                code = self._email_code(email)
                steps.append(f"{realm}: email code page, entered the emailed code")
                resp = self.s.post(_form_action(page, "kc-email-code-login-form"), data={"code": code}, allow_redirects=False)
                continue
            if 'id="kc-totp-settings-form"' in page:
                found = re.search(r'name="totpSecret"[^>]*value="([^"]+)"', page)
                if not found:
                    raise RuntimeError("TOTP setup page has no totpSecret field")
                secret = html.unescape(found.group(1))
                self.totp_secrets[user] = secret
                steps.append(f"{realm}: TOTP setup page, configured an authenticator")
                resp = self.s.post(_form_action(page, "kc-totp-settings-form"),
                                   data={"totp": totp_code(secret), "totpSecret": secret, "userLabel": "e2e"},
                                   allow_redirects=False)
                continue
            if 'id="kc-otp-login-form"' in page:
                if any("TOTP code page" in x for x in steps):
                    steps.append(f"{realm}: TOTP code refused")
                    break
                steps.append(f"{realm}: TOTP code page, entered the current code")
                resp = self.s.post(_form_action(page, "kc-otp-login-form"),
                                   data={"otp": totp_code(self.totp_secrets[user])}, allow_redirects=False)
                continue
            title = re.search(r'<h1[^>]*id="kc-page-title"[^>]*>\s*(.*?)\s*</h1>', page, re.S)
            err = re.search(r'class="[^"]*(kc-feedback-text|alert-error|pf-m-danger)[^"]*"[^>]*>\s*(.*?)\s*<', page, re.S)
            text = html.unescape(re.sub("<[^>]+>", "", title.group(1))).strip() if title else str(resp.status_code)
            steps.append(f"{realm}: stopped at page '{text}'" + (f" ({html.unescape(err.group(2)).strip()})" if err else ""))
            return {"outcome": "refused" if err else "did not complete", "steps": steps}
        return {"outcome": "did not complete", "steps": steps}

    def _amfa_in_tokens(self, code: str, verifier: str) -> bool:
        tok = requests.post(f"{self.kc}/realms/{REALM}/protocol/openid-connect/token", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": CLIENT, "code_verifier": verifier}, timeout=10).json()
        access, ident = _claims(tok["access_token"]), _claims(tok["id_token"])
        text = json.dumps(access) + json.dumps(ident)
        return any(k.startswith("amfa") for k in list(access) + list(ident)) or SCREEN in text or "Safari" in text

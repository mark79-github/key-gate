from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from flask import abort, request
from werkzeug.exceptions import TooManyRequests

from jsonstore import audit, find_client
from ratelimit import LIMIT, WINDOW, record_failure, retry_after

CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_TOKEN_LEN = 200


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token(client_id: str) -> str:
    return f"{client_id}.{secrets.token_urlsafe(32)}"


def _fail(reason: str, client_id: str | None = None):
    ip = request.remote_addr
    count = record_failure(ip)
    audit("auth_failed", reason=reason, client=client_id, ip=ip, path=request.path)
    if count == LIMIT:
        audit("auth_lockout", ip=ip, failures=count, window_seconds=WINDOW)
    abort(401)


def authenticate() -> dict:
    wait = retry_after(request.remote_addr)
    if wait:
        raise TooManyRequests("Too many failed authentication attempts", retry_after=wait)

    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        _fail("missing_or_malformed_header")
    token = header[7:].strip()
    if len(token) > MAX_TOKEN_LEN:
        _fail("token_too_long")

    client_id = token.partition(".")[0]
    if not CLIENT_ID_RE.match(client_id):
        _fail("malformed_client_id")

    client = find_client(client_id)

    expected = client["token_hash"] if client else "0" * 64
    token_ok = hmac.compare_digest(hash_token(token), expected)

    if not client:
        _fail("unknown_client", client_id)
    if not token_ok:
        _fail("bad_token", client_id)
    if client.get("active") is not True:
        _fail("client_revoked", client_id)
    return client

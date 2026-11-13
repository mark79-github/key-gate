import base64
import hashlib
import hmac
import os
import re
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_VAR_RE = re.compile(r"^MASTER_KEY_([A-Za-z0-9]{1,16})$")


@lru_cache(maxsize=1)
def load_keys() -> dict:
    keys = {}
    for var, raw in os.environ.items():
        m = _KEY_VAR_RE.match(var)
        if m:
            try:
                key = base64.b64decode(raw.strip())
            except ValueError:
                raise RuntimeError(f"{var} is not valid base64")
            if len(key) != 32:
                raise RuntimeError(f"{var} must be base64 of exactly 32 bytes")
            keys[m.group(1)] = key
    return keys


def active_key_id() -> str:
    kid = os.environ.get("ACTIVE_KEY_ID", "").strip()
    if not kid:
        raise RuntimeError("ACTIVE_KEY_ID is not set")
    return kid


@lru_cache(maxsize=None)
def _aes(key_id: str) -> AESGCM:
    key = load_keys().get(key_id)
    if key is None:
        raise RuntimeError(f"no key configured for key id {key_id!r}")
    return AESGCM(key)


def key_fingerprint(key_id: str) -> str:
    return hmac.new(load_keys()[key_id], b"manage.py:key-fingerprint:v1", hashlib.sha256).hexdigest()[:8]


def _aad(name: str, version: int) -> bytes:
    return f"{name}|{version}".encode("utf-8")


def blob_key_id(blob: str) -> str:
    return blob.partition(":")[0]


def encrypt(name: str, plaintext: str, version: int, key_id: str) -> str:
    nonce = os.urandom(12)
    ct = _aes(key_id).encrypt(nonce, plaintext.encode("utf-8"), _aad(name, version))
    return f"{key_id}:{base64.b64encode(nonce + ct).decode('ascii')}"


def decrypt(name: str, blob: str, version: int) -> str:
    key_id, _, body = blob.partition(":")
    raw = base64.b64decode(body)
    return _aes(key_id).decrypt(raw[:12], raw[12:], _aad(name, version)).decode("utf-8")

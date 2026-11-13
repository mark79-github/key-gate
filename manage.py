#!/usr/bin/env python3
import argparse
import base64
import getpass
import os
import re
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authentication import CLIENT_ID_RE, hash_token, new_token  # noqa: E402
from encryption import (active_key_id, blob_key_id, decrypt, encrypt,  # noqa: E402
                        key_fingerprint, load_keys)
from jsonstore import (SECRETS_FILE, audit as _audit, load_clients, load_secrets,  # noqa: E402
                       save_clients, save_secrets, write_lock)

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def die(msg: str):
    sys.exit(f"error: {msg}")


def audit(event: str, **fields) -> None:
    """Audit wrapper that records which OS user ran the admin command."""
    try:
        admin = getpass.getuser()
    except Exception:
        admin = "unknown"
    _audit(event, admin=admin, source="manage.py", **fields)


def _find(data: dict, client_id: str) -> dict:
    for c in data["clients"]:
        if c.get("id") == client_id:
            return c
    die("unknown client")


# ---------------------------------------------------------------- clients ---

def create_client(a):
    if not CLIENT_ID_RE.match(a.id):
        die("client id must match [A-Za-z0-9_-]{1,64}")
    with write_lock():
        data = load_clients()
        if any(c.get("id") == a.id for c in data["clients"]):
            die("client id already exists")
        token = new_token(a.id)
        data["clients"].append({"id": a.id, "token_hash": hash_token(token), "active": True})
        save_clients(data)
    audit("client_created", client=a.id)
    print(f"client: {a.id}\ntoken:  {token}\n(store it now; it cannot be shown again)")


def rotate_token(a):
    """Issue a new token for an existing client. The old token stops working immediately."""
    with write_lock():
        data = load_clients()
        token = new_token(a.id)
        _find(data, a.id)["token_hash"] = hash_token(token)
        save_clients(data)
    audit("token_rotated", client=a.id)
    print(f"client: {a.id}\ntoken:  {token}\n(store it now; it cannot be shown again; the old token is now invalid)")


def _set_active(client_id: str, active: bool):
    with write_lock():
        data = load_clients()
        _find(data, client_id)["active"] = active
        save_clients(data)
    audit("client_activated" if active else "client_revoked", client=client_id)
    print("activated" if active else "revoked")


def list_clients(_):
    stored = load_secrets()["secrets"]
    for c in load_clients()["clients"]:
        status = "active" if c.get("active") is True else "REVOKED"
        names = ", ".join(sorted(stored.get(c.get("id"), {}))) or "(none)"
        print(f"{c.get('id', '?'):<20} {status:<8} secrets: {names}")


# ------------------------------------------------------------------- keys ---

def _require_keys() -> str:
    """Validate the key configuration and return the active key id."""
    try:
        keys = load_keys()
        active = active_key_id()
    except RuntimeError as e:
        die(str(e))
    if active not in keys:
        die(f"no key configured for ACTIVE_KEY_ID={active!r} (set MASTER_KEY_{active})")
    return active


def generate_key(_):
    """Print a new random 32-byte key (base64). Put it straight into an environment variable."""
    print(base64.b64encode(os.urandom(32)).decode("ascii"))
    print("Set it as MASTER_KEY_<id> (e.g. MASTER_KEY_1) in the server AND admin environments.",
          file=sys.stderr)


def rotate_key(a):
    """Re-encrypt every secret that isn't under the active key."""
    active = _require_keys()
    with write_lock():
        data = load_secrets()
        todo = [(c, n) for c, names in sorted(data["secrets"].items())
                for n, entry in sorted(names.items())
                if blob_key_id(entry["value"]) != active]
        if not todo:
            print(f"nothing to do: every secret is already under key {active}")
            return
        if a.dry_run:
            for c, n in todo:
                print(f"  would re-encrypt {c}/{n}")
            print(f"{len(todo)} secret(s) would move to key {active} (dry run, nothing written)")
            return

        used = set()
        for client_id, name in todo:  # in memory only; nothing is saved unless everything succeeds
            entry = data["secrets"][client_id][name]
            label = f"{client_id}/{name}"
            try:
                plaintext = decrypt(label, entry["value"], entry["version"])
            except Exception as e:
                die(f"cannot decrypt {label} ({type(e).__name__}); nothing was changed")
            used.add(blob_key_id(entry["value"]))
            entry["value"] = encrypt(label, plaintext, entry["version"], active)  # same version

        backup = f"{SECRETS_FILE}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(SECRETS_FILE, backup)
        os.chmod(backup, 0o600)
        save_secrets(data)
    audit("key_rotated", to_key=active, from_keys=sorted(used), count=len(todo))
    print(f"re-encrypted {len(todo)} secret(s) under key {active}")
    print(f"backup of the previous file: {backup}")
    print("(it is still encrypted under the old key(s): delete it once you've verified everything)")


# ---------------------------------------------------------------- secrets ---

def _check(client_id: str, name: str):
    if not NAME_RE.match(name):
        die("name must match [A-Za-z0-9._-]{1,128}")
    _find(load_clients(), client_id)  # client must exist


def _write_secret(a, mode: str):
    _check(a.client, a.name)
    active = _require_keys()  # fail before prompting for a value
    exists = a.name in load_secrets()["secrets"].get(a.client, {})
    if mode == "create" and exists:
        die(f"{a.client}/{a.name} already exists (use update-secret to change its value)")
    if mode == "update" and not exists:
        die(f"{a.client}/{a.name} does not exist (use create-secret first)")
    if a.stdin:
        value = sys.stdin.read().rstrip("\n")
    else:
        value = getpass.getpass("Value: ")
        if value != getpass.getpass("Repeat: "):
            die("values do not match")
    if not value:
        die("empty value")
    with write_lock():
        data = load_secrets()
        own = data["secrets"].setdefault(a.client, {})
        version = own[a.name]["version"] + 1 if a.name in own else 1
        own[a.name] = {"value": encrypt(f"{a.client}/{a.name}", value, version, active), "version": version}
        save_secrets(data)
    audit("secret_created" if mode == "create" else "secret_updated",
          client=a.client, secret=a.name, version=version, key=active)
    print(f"{a.client}/{a.name} {'created' if mode == 'create' else 'updated'} (version {version})")


def create_secret(a):
    _write_secret(a, "create")


def update_secret(a):
    _write_secret(a, "update")


def delete_secret(a):
    _check(a.client, a.name)
    with write_lock():
        data = load_secrets()
        own = data["secrets"].get(a.client, {})
        if a.name not in own:
            die("unknown secret")
        version = own.pop(a.name)["version"]
        if not own:
            data["secrets"].pop(a.client, None)
        save_secrets(data)
    audit("secret_deleted", client=a.client, secret=a.name, version=version)
    print("deleted")


def list_secrets(a):
    for client_id, names in sorted(load_secrets()["secrets"].items()):
        if a.client is None or a.client == client_id:
            for name, entry in sorted(names.items()):
                print(f"  {client_id:<20} {name:<30} v{entry['version']}")


def verify(_):
    """Check that the configured keys can decrypt every stored secret."""
    active = _require_keys()
    print("Configured keys (compare fingerprints across environments):")
    for kid in sorted(load_keys()):
        print(f"  key {kid}{' (active)' if kid == active else ''}: fingerprint {key_fingerprint(kid)}")
    print()

    failed = stale = 0
    for client_id, names in sorted(load_secrets()["secrets"].items()):
        for name, entry in sorted(names.items()):
            label = f"{client_id}/{name}"
            try:
                decrypt(label, entry["value"], entry["version"])
                kid = blob_key_id(entry["value"])
                stale += kid != active
                print(f"  OK      {label}  (key {kid})")
            except Exception as e:
                failed += 1
                reason = str(e) if isinstance(e, RuntimeError) else type(e).__name__
                print(f"  FAILED  {label}  ({reason})")

    if failed:
        print(f"\n{failed} failed: wrong or missing key, or the entry was edited, renamed, "
              "or had its version changed.")
    elif stale:
        print(f"\n{stale} secret(s) are not under the active key: run 'rotate-key'.")
    sys.exit(1 if failed else 0)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("create-client"); s.add_argument("id"); s.set_defaults(fn=create_client)
    s = sub.add_parser("rotate-token"); s.add_argument("id"); s.set_defaults(fn=rotate_token)
    s = sub.add_parser("revoke-client"); s.add_argument("id"); s.set_defaults(fn=lambda a: _set_active(a.id, False))
    s = sub.add_parser("activate-client"); s.add_argument("id"); s.set_defaults(fn=lambda a: _set_active(a.id, True))
    s = sub.add_parser("list-clients"); s.set_defaults(fn=list_clients)
    for cmd, fn in (("create-secret", create_secret), ("update-secret", update_secret)):
        s = sub.add_parser(cmd); s.add_argument("client"); s.add_argument("name")
        s.add_argument("--stdin", action="store_true"); s.set_defaults(fn=fn)
    s = sub.add_parser("delete-secret"); s.add_argument("client"); s.add_argument("name"); s.set_defaults(fn=delete_secret)
    s = sub.add_parser("list-secrets"); s.add_argument("client", nargs="?"); s.set_defaults(fn=list_secrets)
    s = sub.add_parser("verify"); s.set_defaults(fn=verify)
    s = sub.add_parser("generate-key"); s.set_defaults(fn=generate_key)
    s = sub.add_parser("rotate-key")
    s.add_argument("--dry-run", action="store_true", help="show what would change, write nothing")
    s.set_defaults(fn=rotate_key)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

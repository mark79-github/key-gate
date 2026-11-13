import json
import logging
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

try:  # Linux / macOS
    import fcntl
except ImportError:  # Windows
    fcntl = None
    import msvcrt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.environ.get("STORAGE_DIR", os.path.join(BASE_DIR, "storage"))
CLIENTS_FILE = os.path.join(STORAGE_DIR, "clients.json")
SECRETS_FILE = os.path.join(STORAGE_DIR, "secrets.json")
AUDIT_FILE = os.path.join(STORAGE_DIR, "audit.log")
LOCK_FILE = os.path.join(STORAGE_DIR, ".lock")
AUDIT_LOCK_FILE = os.path.join(STORAGE_DIR, ".audit.lock")

AUDIT_MAX_BYTES = int(os.environ.get("AUDIT_MAX_BYTES", 5 * 1024 * 1024))
AUDIT_KEEP = int(os.environ.get("AUDIT_KEEP", "5"))

log = logging.getLogger(__name__)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_dir() -> None:
    os.makedirs(STORAGE_DIR, mode=0o700, exist_ok=True)


@contextmanager
def _locked(path: str):
    _ensure_dir()
    with open(path, "a+b") as lf:
        if fcntl:
            fcntl.flock(lf, fcntl.LOCK_EX)
        else:
            while True:
                try:
                    lf.seek(0)
                    msvcrt.locking(lf.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    continue
        try:
            yield
        finally:
            if fcntl:
                fcntl.flock(lf, fcntl.LOCK_UN)
            else:
                lf.seek(0)
                msvcrt.locking(lf.fileno(), msvcrt.LK_UNLCK, 1)


def write_lock():
    return _locked(LOCK_FILE)


def _load(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _save(path: str, data: dict) -> None:
    _ensure_dir()
    fd, tmp = tempfile.mkstemp(dir=STORAGE_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        for attempt in range(20):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def load_clients() -> dict:
    data = _load(CLIENTS_FILE)
    data.setdefault("clients", [])
    return data


def save_clients(data: dict) -> None:
    _save(CLIENTS_FILE, data)


_clients_lock = threading.Lock()
_clients_cache = (None, {})


def _file_sig(path: str):
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    return (st.st_ino, st.st_mtime_ns, st.st_size)


def find_client(client_id: str):
    global _clients_cache
    sig = _file_sig(CLIENTS_FILE)
    cached_sig, index = _clients_cache
    if sig != cached_sig:
        with _clients_lock:
            cached_sig, index = _clients_cache
            if sig != cached_sig:
                index = {}
                for c in load_clients()["clients"]:
                    if isinstance(c, dict) and "id" in c:
                        index.setdefault(c["id"], c)
                _clients_cache = (sig, index)
    return index.get(client_id)


def load_secrets() -> dict:
    data = _load(SECRETS_FILE)
    data.setdefault("secrets", {})
    return data


def save_secrets(data: dict) -> None:
    _save(SECRETS_FILE, data)


def _rotate_audit() -> None:
    for i in range(AUDIT_KEEP - 1, 0, -1):
        src = f"{AUDIT_FILE}.{i}"
        if os.path.exists(src):
            os.replace(src, f"{AUDIT_FILE}.{i + 1}")
    os.replace(AUDIT_FILE, f"{AUDIT_FILE}.1")


def audit(event: str, **fields) -> None:
    line = json.dumps({"ts": now(), "event": event, **fields}) + "\n"

    with _locked(AUDIT_LOCK_FILE):
        try:
            if os.path.getsize(AUDIT_FILE) >= AUDIT_MAX_BYTES:
                _rotate_audit()
        except FileNotFoundError:
            pass
        except OSError as e:
            log.error("audit log rotation failed: %s: %s", type(e).__name__, e)
        fd = os.open(AUDIT_FILE, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)

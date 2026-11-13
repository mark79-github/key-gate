import ipaddress
import logging
import os
import sqlite3
import time
from contextlib import closing

from jsonstore import STORAGE_DIR, _ensure_dir

LIMIT = int(os.environ.get("FAILED_AUTH_LIMIT", "10"))
WINDOW = int(os.environ.get("FAILED_AUTH_WINDOW", "300"))  # seconds
DB_PATH = os.path.join(STORAGE_DIR, "ratelimit.sqlite3")

log = logging.getLogger(__name__)
_initialized = False


def _key(ip) -> str:
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return str(ip)[:64]
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def _connect() -> sqlite3.Connection:
    global _initialized
    _ensure_dir()
    if not os.path.exists(DB_PATH):
        os.close(os.open(DB_PATH, os.O_CREAT | os.O_WRONLY, 0o600))
    conn = sqlite3.connect(DB_PATH, timeout=2, isolation_level=None)
    if not _initialized:
        conn.execute("CREATE TABLE IF NOT EXISTS failures (key TEXT NOT NULL, ts INTEGER NOT NULL)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_failures_key_ts ON failures (key, ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_failures_ts ON failures (ts)")
        _initialized = True
    return conn


def retry_after(ip) -> int:
    try:
        now = int(time.time())
        with closing(_connect()) as conn:
            count, oldest = conn.execute(
                "SELECT COUNT(*), MIN(ts) FROM failures WHERE key = ? AND ts > ?",
                (_key(ip), now - WINDOW),
            ).fetchone()
    except sqlite3.Error as e:
        log.error("ratelimit check failed (failing open): %s: %s", type(e).__name__, e)
        return 0
    if count >= LIMIT:
        return max(1, oldest + WINDOW - now)
    return 0


def record_failure(ip) -> int:
    try:
        now = int(time.time())
        key = _key(ip)
        with closing(_connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("DELETE FROM failures WHERE ts <= ?", (now - WINDOW,))
                count = conn.execute("SELECT COUNT(*) FROM failures WHERE key = ?", (key,)).fetchone()[0]
                if count < LIMIT:
                    conn.execute("INSERT INTO failures (key, ts) VALUES (?, ?)", (key, now))
                    count += 1
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return count
    except sqlite3.Error as e:
        log.error("ratelimit record failed (failing open): %s: %s", type(e).__name__, e)
        return 0

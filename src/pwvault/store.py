"""SQLite storage shared by the owner's CLI and the server process.

The database holds only ciphertext, hashes and policy data. It never holds the
master password, the vault key, a share secret or a PIN.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from pwvault import crypto
from pwvault.entries import EncryptedEntry

# Seconds since the Unix epoch. Injectable so tests can move time forward.
Clock = Callable[[], int]


def system_clock() -> int:
    return int(time.time())


class ShareStatus:
    ACTIVE = "active"
    USED = "used"  # use limit reached
    EXPIRED = "expired"  # time ran out, or 3 wrong PINs
    REVOKED = "revoked"  # owner revoked it
    ENDED = "ended"  # password changed or entry deleted


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- One row per vault entry. Everything except the ID and version is ciphertext.
CREATE TABLE IF NOT EXISTS entries (
    id          TEXT PRIMARY KEY,
    version     INTEGER NOT NULL,
    wrapped_key BLOB NOT NULL,   -- entry key, encrypted under the vault key
    meta_ct     BLOB NOT NULL,   -- name, username, url
    secret_ct   BLOB NOT NULL,   -- password, notes
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
    id              TEXT PRIMARY KEY,
    entry_id        TEXT NOT NULL,
    token_hash      BLOB NOT NULL,   -- SHA-256 of the lookup token
    blob            BLOB,            -- NULL once the share is no longer active
    has_pin         INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    uses_left       INTEGER NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS shares_by_entry ON shares (entry_id, status);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    created_at INTEGER NOT NULL,
    last_used  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_state (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    failures     INTEGER NOT NULL,
    locked_until INTEGER NOT NULL,
    lock_minutes INTEGER NOT NULL
);
INSERT OR IGNORE INTO login_state (id, failures, locked_until, lock_minutes)
VALUES (1, 0, 0, 15);

-- Failed logins, wrong PINs and expired shares are only ever written here.
CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    event   TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail  TEXT NOT NULL
);
"""


def connect(path: str | Path, *, create_schema: bool = True) -> sqlite3.Connection:
    """Opens (creating if needed) the database. Pass ":memory:" for tests.

    The server creates the schema once at startup and skips it per request.
    """
    conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    if create_schema:
        if str(path) != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")  # lets the CLI and server share the file
        conn.executescript(_SCHEMA)
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """BEGIN IMMEDIATE ... COMMIT, rolled back on any exception."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def meta_get(conn: sqlite3.Connection, key: str) -> bytes | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else bytes(row["value"])


def meta_set(conn: sqlite3.Connection, key: str, value: bytes) -> None:
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


def save_kdf_settings(conn: sqlite3.Connection, salt: bytes, params: crypto.KdfParams) -> None:
    meta_set(conn, "kdf_salt", salt)
    meta_set(conn, "kdf_opslimit", str(params.opslimit).encode())
    meta_set(conn, "kdf_memlimit", str(params.memlimit).encode())


def load_kdf_settings(conn: sqlite3.Connection) -> tuple[bytes, crypto.KdfParams] | None:
    """The master-password salt and Argon2id settings (public), or None if no vault."""
    salt, ops, mem = (meta_get(conn, k) for k in ("kdf_salt", "kdf_opslimit", "kdf_memlimit"))
    if salt is None or ops is None or mem is None:
        return None
    return salt, crypto.KdfParams(opslimit=int(ops), memlimit=int(mem))


# ---- Entries (ciphertext only) -------------------------------------------------


_ENTRY_COLUMNS = "SELECT id, version, wrapped_key, meta_ct, secret_ct FROM entries"


def _to_entry(row: sqlite3.Row) -> EncryptedEntry:
    return EncryptedEntry(
        row["id"], row["version"], row["wrapped_key"], row["meta_ct"], row["secret_ct"]
    )


def load_entry(conn: sqlite3.Connection, entry_id: str) -> EncryptedEntry | None:
    row = conn.execute(f"{_ENTRY_COLUMNS} WHERE id = ?", (entry_id,)).fetchone()  # noqa: S608
    return None if row is None else _to_entry(row)


def load_all_entries(conn: sqlite3.Connection) -> list[EncryptedEntry]:
    return [_to_entry(r) for r in conn.execute(_ENTRY_COLUMNS)]


def save_entry(conn: sqlite3.Connection, entry: EncryptedEntry, now: int) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO entries (id, version, wrapped_key, meta_ct, secret_ct, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (entry.id, entry.version, entry.wrapped_key, entry.meta_ct, entry.secret_ct, now),
    )


@dataclass(frozen=True)
class AuditEvent:
    id: int
    timestamp: int
    event: str
    subject: str
    detail: str


def audit(conn: sqlite3.Connection, now: int, event: str, subject: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO audit (ts, event, subject, detail) VALUES (?, ?, ?, ?)",
        (now, event, subject, detail),
    )


def audit_recent(conn: sqlite3.Connection, limit: int = 50) -> list[AuditEvent]:
    rows = conn.execute(
        "SELECT id, ts, event, subject, detail FROM audit ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [AuditEvent(r["id"], r["ts"], r["event"], r["subject"], r["detail"]) for r in rows]


def expire_due_shares(conn: sqlite3.Connection, now: int) -> None:
    """Marks shares past their time limit as expired and deletes their blobs, so
    an encrypted password doesn't linger in the database after its share ends."""
    ids = [
        r["id"]
        for r in conn.execute(
            "SELECT id FROM shares WHERE status = ? AND expires_at <= ?",
            (ShareStatus.ACTIVE, now),
        )
    ]
    for share_id in ids:
        conn.execute(
            "UPDATE shares SET status = ?, blob = NULL, uses_left = 0 WHERE id = ?",
            (ShareStatus.EXPIRED, share_id),
        )
        audit(conn, now, "share.expired", share_id, "time limit reached")


def end_shares_for_entry(conn: sqlite3.Connection, entry_id: str, now: int, reason: str) -> int:
    """Ends every active share for an entry and deletes their blobs.

    Call inside the same transaction as the password change. Returns how many ended.
    """
    ids = [
        r["id"]
        for r in conn.execute(
            "SELECT id FROM shares WHERE entry_id = ? AND status = ?",
            (entry_id, ShareStatus.ACTIVE),
        )
    ]
    conn.execute(
        "UPDATE shares SET status = ?, blob = NULL WHERE entry_id = ? AND status = ?",
        (ShareStatus.ENDED, entry_id, ShareStatus.ACTIVE),
    )
    for share_id in ids:
        audit(conn, now, "share.ended", share_id, reason)
    return len(ids)

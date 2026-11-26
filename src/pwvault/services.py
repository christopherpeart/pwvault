"""Server-side rules: share redemption and master-password login.

These hold no keys. They compare hashes, enforce limits and write the audit
log. Kept free of HTTP so they can be tested directly.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import Enum

from pwvault import crypto, store
from pwvault.store import Clock, ShareStatus, system_clock

MAX_PIN_ATTEMPTS = 3
LOGIN_MAX_FAILURES = 5
SESSION_IDLE_SECONDS = 15 * 60
TOKEN_SIZE = 32


# ---- Shares -----------------------------------------------------------------


class RedeemStatus(Enum):
    OK = "ok"
    ENDED = "ended"  # unknown, used, expired, revoked or ended: all look the same
    WRONG_TOKEN = "wrong_token"  # noqa: S105 (status name) - wrong PIN; attempts remain
    EXPIRED_NOW = "expired_now"  # this wrong PIN was the last allowed attempt


@dataclass(frozen=True)
class RedeemResult:
    status: RedeemStatus
    blob: bytes | None = None
    attempts_left: int = 0


@dataclass(frozen=True)
class ShareAvailability:
    has_pin: bool
    active: bool


class ShareService:
    def __init__(self, conn: sqlite3.Connection, clock: Clock = system_clock) -> None:
        self._conn = conn
        self._clock = clock

    def info(self, share_id: str) -> ShareAvailability:
        """Public: tells the redeem page whether to ask for a PIN."""
        with store.transaction(self._conn):
            store.expire_due_shares(self._conn, self._clock())
        row = self._conn.execute(
            "SELECT has_pin, status, expires_at FROM shares WHERE id = ?", (share_id,)
        ).fetchone()
        if row is None:
            return ShareAvailability(has_pin=False, active=False)
        active = row["status"] == ShareStatus.ACTIVE and self._clock() < row["expires_at"]
        return ShareAvailability(has_pin=bool(row["has_pin"]), active=active)

    def redeem(self, share_id: str, lookup_token: bytes, client: str = "") -> RedeemResult:
        now = self._clock()
        with store.transaction(self._conn):
            store.expire_due_shares(self._conn, now)
            row = self._conn.execute(
                "SELECT token_hash, blob, uses_left, failed_attempts, status"
                " FROM shares WHERE id = ?",
                (share_id,),
            ).fetchone()
            if row is None:
                # Not logged: anyone can send random IDs, and they'd flood the log.
                return RedeemResult(RedeemStatus.ENDED)
            if row["status"] != ShareStatus.ACTIVE:
                store.audit(
                    self._conn, now, "share.redeem_inactive", share_id, f"{row['status']} {client}"
                )
                return RedeemResult(RedeemStatus.ENDED)

            if not crypto.constant_time_equal(crypto.sha256(lookup_token), row["token_hash"]):
                failures = row["failed_attempts"] + 1
                self._conn.execute(
                    "UPDATE shares SET failed_attempts = ? WHERE id = ?", (failures, share_id)
                )
                store.audit(self._conn, now, "share.pin_failed", share_id, client)
                if failures < MAX_PIN_ATTEMPTS:
                    return RedeemResult(
                        RedeemStatus.WRONG_TOKEN, attempts_left=MAX_PIN_ATTEMPTS - failures
                    )
                # Expired for good: blob deleted, link and PIN stop working.
                self._finish(share_id, ShareStatus.EXPIRED)
                store.audit(
                    self._conn, now, "share.expired", share_id, f"{MAX_PIN_ATTEMPTS} wrong PINs"
                )
                return RedeemResult(RedeemStatus.EXPIRED_NOW)

            blob = bytes(row["blob"])
            uses_left = row["uses_left"] - 1
            if uses_left <= 0:
                self._finish(share_id, ShareStatus.USED)
            else:
                self._conn.execute(
                    "UPDATE shares SET uses_left = ? WHERE id = ?", (uses_left, share_id)
                )
            store.audit(
                self._conn, now, "share.redeemed", share_id, f"uses_left={uses_left} {client}"
            )
            return RedeemResult(RedeemStatus.OK, blob=blob)

    def _finish(self, share_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE shares SET status = ?, blob = NULL, uses_left = 0 WHERE id = ?",
            (status, share_id),
        )


# ---- Login and sessions -------------------------------------------------------


class LoginStatus(Enum):
    OK = "ok"
    WRONG = "wrong"
    LOCKED = "locked"
    NOT_INITIALIZED = "not_initialized"


@dataclass(frozen=True)
class LoginResult:
    status: LoginStatus
    token: str | None = None
    locked_until: int | None = None


class AuthService:
    def __init__(self, conn: sqlite3.Connection, clock: Clock = system_clock) -> None:
        self._conn = conn
        self._clock = clock

    def login(self, auth_key: bytes, client: str = "") -> LoginResult:
        now = self._clock()
        auth_hash = store.meta_get(self._conn, "auth_hash")
        if auth_hash is None:
            return LoginResult(LoginStatus.NOT_INITIALIZED)
        with store.transaction(self._conn):
            state = self._conn.execute(
                "SELECT failures, locked_until, lock_minutes FROM login_state WHERE id = 1"
            ).fetchone()
            if now < state["locked_until"]:
                # Not logged: the lock itself is, and attempts during it can't succeed.
                return LoginResult(LoginStatus.LOCKED, locked_until=state["locked_until"])

            if not crypto.verify_stored_hash(auth_hash, auth_key):
                failures = state["failures"] + 1
                store.audit(self._conn, now, "login.failed", "login", client)
                if failures >= LOGIN_MAX_FAILURES:
                    # Lock for lock_minutes, doubling each time it happens.
                    locked_until = now + state["lock_minutes"] * 60
                    self._conn.execute(
                        "UPDATE login_state SET failures = 0, locked_until = ?,"
                        " lock_minutes = lock_minutes * 2 WHERE id = 1",
                        (locked_until,),
                    )
                    store.audit(
                        self._conn, now, "login.locked", "login",
                        f"{LOGIN_MAX_FAILURES} failures; {state['lock_minutes']} min",
                    )
                    return LoginResult(LoginStatus.LOCKED, locked_until=locked_until)
                self._conn.execute(
                    "UPDATE login_state SET failures = ? WHERE id = 1", (failures,)
                )
                return LoginResult(LoginStatus.WRONG)

            token = crypto.random_bytes(TOKEN_SIZE)
            self._conn.execute(
                "UPDATE login_state SET failures = 0, locked_until = 0, lock_minutes = 15"
                " WHERE id = 1"
            )
            # Sessions that timed out without being used again are otherwise never removed.
            self._conn.execute(
                "DELETE FROM sessions WHERE last_used < ?", (now - SESSION_IDLE_SECONDS,)
            )
            self._conn.execute(
                "INSERT INTO sessions (token_hash, created_at, last_used) VALUES (?, ?, ?)",
                (crypto.sha256(token), now, now),
            )
            store.audit(self._conn, now, "login.ok", "login", client)
            return LoginResult(LoginStatus.OK, token=crypto.b64e(token))

    def validate(self, token: str) -> bool:
        """True if the session exists and was used in the last 15 minutes."""
        try:
            token_hash = crypto.sha256(crypto.b64d(token))
        except crypto.CryptoError:
            return False
        now = self._clock()
        with store.transaction(self._conn):
            row = self._conn.execute(
                "SELECT last_used FROM sessions WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                return False
            if now - row["last_used"] > SESSION_IDLE_SECONDS:
                self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return False
            self._conn.execute(
                "UPDATE sessions SET last_used = ? WHERE token_hash = ?", (now, token_hash)
            )
            return True

    def logout(self, token: str) -> None:
        try:
            token_hash = crypto.sha256(crypto.b64d(token))
        except crypto.CryptoError:
            return
        self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

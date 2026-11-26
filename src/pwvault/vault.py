"""The owner's vault: create, unlock, manage entries and create shares.

Runs on the owner's machine with direct access to the database. It is the only
component that ever holds the vault key.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from pwvault import crypto, shares, store
from pwvault.entries import (
    EncryptedEntry,
    EntryMeta,
    EntrySecret,
    derive_owner_keys,
    new_id,
    open_meta,
    open_secret,
    seal_entry,
)
from pwvault.store import Clock, ShareStatus, system_clock


class VaultError(Exception):
    pass


class AlreadyInitialized(VaultError):
    pass


class NotInitialized(VaultError):
    pass


class WrongPassword(VaultError):
    pass


class EntryNotFound(VaultError):
    pass


class ShareNotFound(VaultError):
    pass


@dataclass(frozen=True)
class ShareOptions:
    ttl_seconds: int = 24 * 3600
    max_uses: int = 1
    with_pin: bool = False


@dataclass(frozen=True)
class ShareInvite:
    share_id: str
    secret: bytes
    pin: str | None
    expires_at: int

    def url(self, base_url: str) -> str:
        return shares.format_share_url(base_url, self.share_id, self.secret)


@dataclass(frozen=True)
class ShareRecord:
    id: str
    entry_id: str
    status: str
    has_pin: bool
    created_at: int
    expires_at: int
    uses_left: int
    failed_attempts: int


def is_initialized(conn: sqlite3.Connection) -> bool:
    return store.meta_get(conn, "auth_hash") is not None


class Vault:
    """An unlocked vault. Create with Vault.create() or Vault.unlock()."""

    def __init__(self, conn: sqlite3.Connection, vault_key: bytes, clock: Clock) -> None:
        self._conn = conn
        self._key = vault_key
        self._clock = clock

    # ---- Lifecycle ----------------------------------------------------------

    @classmethod
    def create(
        cls,
        conn: sqlite3.Connection,
        master_password: str,
        *,
        params: crypto.KdfParams = crypto.MASTER_KDF,
        auth_params: crypto.KdfParams = crypto.AUTH_HASH_KDF,
        clock: Clock = system_clock,
    ) -> Vault:
        if is_initialized(conn):
            raise AlreadyInitialized("this database already holds a vault")
        if len(master_password) < 8:
            raise VaultError("master password must be at least 8 characters")
        salt = crypto.random_bytes(crypto.SALT_SIZE)
        vault_key, auth_key = derive_owner_keys(master_password, salt, params)
        with store.transaction(conn):
            store.save_kdf_settings(conn, salt, params)
            store.meta_set(conn, "auth_hash", crypto.hash_for_storage(auth_key, auth_params))
            store.audit(conn, clock(), "vault.created", "vault")
        return cls(conn, vault_key, clock)

    @classmethod
    def unlock(
        cls, conn: sqlite3.Connection, master_password: str, *, clock: Clock = system_clock
    ) -> Vault:
        settings = store.load_kdf_settings(conn)
        auth_hash = store.meta_get(conn, "auth_hash")
        if settings is None or auth_hash is None:
            raise NotInitialized("no vault here yet; run `pwvault init`")
        vault_key, auth_key = derive_owner_keys(master_password, *settings)
        if not crypto.verify_stored_hash(auth_hash, auth_key):
            store.audit(conn, clock(), "unlock.failed", "vault", "wrong master password (local)")
            raise WrongPassword("wrong master password")
        return cls(conn, vault_key, clock)

    # ---- Entries ------------------------------------------------------------

    def add(self, meta: EntryMeta, secret: EntrySecret) -> str:
        entry_id = new_id()
        with store.transaction(self._conn):
            store.save_entry(
                self._conn, seal_entry(self._key, entry_id, 1, meta, secret), self._clock()
            )
            store.audit(self._conn, self._clock(), "entry.added", entry_id)
        return entry_id

    def list_entries(self) -> list[tuple[str, EntryMeta]]:
        items = [(e.id, open_meta(self._key, e)) for e in store.load_all_entries(self._conn)]
        return sorted(items, key=lambda item: item[1].name.lower())

    def get(self, entry_id: str) -> tuple[EntryMeta, EntrySecret]:
        entry = self._load(entry_id)
        return open_meta(self._key, entry), open_secret(self._key, entry)

    def find(self, query: str) -> str:
        """Resolves an exact ID, a unique ID prefix (4+ characters), or a name."""
        items = self.list_entries()
        if any(entry_id == query for entry_id, _ in items):
            return query
        matches = [i for i, m in items if m.name.lower() == query.lower()] or [
            i for i, _ in items if len(query) >= 4 and i.startswith(query)
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise EntryNotFound(f"no entry matches {query!r}")
        raise EntryNotFound(f"{query!r} matches {len(matches)} entries; use the ID")

    def update(self, entry_id: str, meta: EntryMeta, secret: EntrySecret) -> int:
        """Saves new values. If the password changed, every active share for
        this entry ends in the same transaction. Returns how many shares ended."""
        current = self._load(entry_id)
        password_changed = secret.password != open_secret(self._key, current).password
        now = self._clock()
        with store.transaction(self._conn):
            sealed = seal_entry(self._key, entry_id, current.version + 1, meta, secret)
            store.save_entry(self._conn, sealed, now)
            store.audit(self._conn, now, "entry.updated", entry_id)
            if not password_changed:
                return 0
            return store.end_shares_for_entry(self._conn, entry_id, now, "password changed")

    def remove(self, entry_id: str) -> int:
        self._load(entry_id)
        now = self._clock()
        with store.transaction(self._conn):
            ended = store.end_shares_for_entry(self._conn, entry_id, now, "entry deleted")
            self._conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            store.audit(self._conn, now, "entry.deleted", entry_id)
        return ended

    # ---- Shares -------------------------------------------------------------

    def create_share(
        self,
        entry_id: str,
        options: ShareOptions = ShareOptions(),  # noqa: B008 - frozen dataclass
        *,
        pin_params: crypto.KdfParams = crypto.PIN_KDF,
    ) -> ShareInvite:
        if options.max_uses < 1 or options.ttl_seconds < 1:
            raise VaultError("a share needs at least one use and a positive lifetime")
        meta, secret = self.get(entry_id)
        share_id = new_id()
        share_secret = crypto.random_bytes(shares.SECRET_SIZE)
        pin = shares.generate_pin() if options.with_pin else None
        keys = shares.derive_share_keys(share_id, share_secret, pin, pin_params)
        blob = shares.seal_share_payload(
            keys.enc_key,
            share_id,
            shares.SharedEntry(name=meta.name, username=meta.username, password=secret.password),
        )
        now = self._clock()
        expires_at = now + options.ttl_seconds
        with store.transaction(self._conn):
            self._conn.execute(
                "INSERT INTO shares (id, entry_id, token_hash, blob, has_pin, created_at,"
                " expires_at, uses_left, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (share_id, entry_id, crypto.sha256(keys.lookup_token), blob, int(pin is not None),
                 now, expires_at, options.max_uses, ShareStatus.ACTIVE),
            )
            store.audit(
                self._conn, now, "share.created", share_id,
                f"entry={entry_id} uses={options.max_uses} pin={'yes' if pin else 'no'}",
            )
        return ShareInvite(share_id, share_secret, pin, expires_at)

    def revoke_share(self, share_id: str) -> None:
        with store.transaction(self._conn):
            cur = self._conn.execute(
                "UPDATE shares SET status = ?, blob = NULL WHERE id = ? AND status = ?",
                (ShareStatus.REVOKED, share_id, ShareStatus.ACTIVE),
            )
            if cur.rowcount == 0:
                raise ShareNotFound(f"no active share {share_id!r}")
            store.audit(self._conn, self._clock(), "share.revoked", share_id)

    def list_shares(self) -> list[ShareRecord]:
        with store.transaction(self._conn):
            store.expire_due_shares(self._conn, self._clock())
        rows = self._conn.execute(
            "SELECT id, entry_id, status, has_pin, created_at, expires_at, uses_left,"
            " failed_attempts FROM shares ORDER BY created_at DESC"
        ).fetchall()
        return [ShareRecord(**{**dict(r), "has_pin": bool(r["has_pin"])}) for r in rows]

    # ---- Internals ----------------------------------------------------------

    def _load(self, entry_id: str) -> EncryptedEntry:
        entry = store.load_entry(self._conn, entry_id)
        if entry is None:
            raise EntryNotFound(f"no entry with ID {entry_id!r}")
        return entry

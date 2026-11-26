from __future__ import annotations

import sqlite3

import pytest
from conftest import MASTER, FakeClock

from pwvault import crypto, store
from pwvault.entries import EntryMeta, EntrySecret
from pwvault.vault import (
    AlreadyInitialized,
    EntryNotFound,
    NotInitialized,
    ShareOptions,
    Vault,
    WrongPassword,
)


def test_unlock_with_right_and_wrong_password(
    conn: sqlite3.Connection, vault: Vault, netflix: str, clock: FakeClock
) -> None:
    again = Vault.unlock(conn, MASTER, clock=clock)
    assert again.get(netflix)[1].password == "hunter2-netflix"

    with pytest.raises(WrongPassword):
        Vault.unlock(conn, "wrong password", clock=clock)
    assert store.audit_recent(conn, 1)[0].event == "unlock.failed"


def test_cannot_create_twice_or_unlock_empty(conn: sqlite3.Connection, vault: Vault) -> None:
    with pytest.raises(AlreadyInitialized):
        Vault.create(conn, MASTER, params=crypto.TEST_KDF, auth_params=crypto.TEST_KDF)
    with pytest.raises(NotInitialized):
        Vault.unlock(store.connect(":memory:"), MASTER)


def test_database_holds_no_plaintext(conn: sqlite3.Connection, vault: Vault, netflix: str) -> None:
    dump = "\n".join(conn.iterdump()).upper()  # blobs are dumped as X'HEX'
    for secret in (b"hunter2-netflix", b"Netflix", b"me@example.com", b"family plan",
                   MASTER.encode()):
        assert secret.decode().upper() not in dump
        assert secret.hex().upper() not in dump


def test_add_list_get_find(vault: Vault, netflix: str) -> None:
    other = vault.add(EntryMeta(name="Email"), EntrySecret(password="pw"))
    assert [m.name for _, m in vault.list_entries()] == ["Email", "Netflix"]
    meta, secret = vault.get(netflix)
    assert (meta.username, secret.notes) == ("me@example.com", "family plan")
    assert vault.find("netflix") == netflix
    assert vault.find(other[:6]) == other
    with pytest.raises(EntryNotFound):
        vault.find("nothing")


def test_update_bumps_version_and_rejects_swapped_ciphertext(
    conn: sqlite3.Connection, vault: Vault, netflix: str
) -> None:
    other = vault.add(EntryMeta(name="Email"), EntrySecret(password="pw"))
    vault.update(netflix, EntryMeta(name="Netflix"), EntrySecret(password="new"))
    row = conn.execute("SELECT version FROM entries WHERE id = ?", (netflix,)).fetchone()
    assert row["version"] == 2

    # Copy Email's ciphertext over Netflix's row: the bound ID/version must catch it.
    conn.execute(
        "UPDATE entries SET wrapped_key = (SELECT wrapped_key FROM entries WHERE id = ?),"
        " secret_ct = (SELECT secret_ct FROM entries WHERE id = ?) WHERE id = ?",
        (other, other, netflix),
    )
    with pytest.raises(crypto.DecryptError):
        vault.get(netflix)


def test_password_change_ends_active_shares(
    conn: sqlite3.Connection, vault: Vault, netflix: str
) -> None:
    vault.create_share(netflix, pin_params=crypto.TEST_KDF)
    vault.create_share(netflix, ShareOptions(with_pin=True), pin_params=crypto.TEST_KDF)

    ended = vault.update(
        netflix, EntryMeta(name="Netflix"), EntrySecret(password="brand-new-password")
    )

    assert ended == 2
    statuses = conn.execute("SELECT status, blob FROM shares").fetchall()
    assert all(r["status"] == "ended" and r["blob"] is None for r in statuses)
    reasons = [e.detail for e in store.audit_recent(conn, 10) if e.event == "share.ended"]
    assert reasons == ["password changed", "password changed"]


def test_non_password_edit_keeps_shares(vault: Vault, netflix: str) -> None:
    vault.create_share(netflix)
    ended = vault.update(
        netflix, EntryMeta(name="Netflix (family)"),
        EntrySecret(password="hunter2-netflix", notes="new note"),
    )
    assert ended == 0
    assert vault.list_shares()[0].status == "active"


def test_remove_ends_shares(vault: Vault, netflix: str) -> None:
    vault.create_share(netflix)
    assert vault.remove(netflix) == 1
    assert vault.list_entries() == []
    assert vault.list_shares()[0].status == "ended"

from __future__ import annotations

import sqlite3

import pytest
from conftest import FakeClock

from pwvault import crypto, shares, store
from pwvault.services import RedeemStatus, ShareService
from pwvault.vault import ShareInvite, ShareNotFound, ShareOptions, Vault

FAST = crypto.TEST_KDF


def _token(invite: ShareInvite, pin: str | None) -> shares.ShareKeys:
    return shares.derive_share_keys(invite.share_id, invite.secret, pin, FAST)


def test_pin_is_six_unambiguous_characters() -> None:
    pins = {shares.generate_pin() for _ in range(200)}
    assert len(shares.PIN_ALPHABET) == 31
    for pin in pins:
        assert len(pin) == 6 and set(pin) <= set(shares.PIN_ALPHABET)
    assert not set("01ILO") & set(shares.PIN_ALPHABET)
    assert len(pins) > 190  # random, not repeating
    assert shares.normalize_pin("ab3-k9 m") == "AB3K9M"


def test_share_url_round_trip() -> None:
    share_id, secret = crypto.b64e(bytes(16)), bytes(range(16))
    url = shares.format_share_url("https://vault.example.com/", share_id, secret)
    assert url == f"https://vault.example.com/s/{share_id}#{crypto.b64e(secret)}"
    parsed = shares.parse_share_url(url)
    assert (parsed.base_url, parsed.share_id, parsed.secret) == (
        "https://vault.example.com", share_id, secret)
    with pytest.raises(ValueError):
        shares.parse_share_url("https://vault.example.com/s/abc")  # no secret


def test_redeem_returns_only_the_shared_account(
    conn: sqlite3.Connection, vault: Vault, netflix: str, clock: FakeClock
) -> None:
    invite = vault.create_share(netflix, pin_params=FAST)
    keys = _token(invite, None)

    result = ShareService(conn, clock).redeem(invite.share_id, keys.lookup_token)

    assert result.status is RedeemStatus.OK and result.blob is not None
    entry = shares.open_share_payload(keys.enc_key, invite.share_id, result.blob)
    assert entry == shares.SharedEntry("Netflix", "me@example.com", "hunter2-netflix")


def test_server_stores_no_secret_or_pin(
    conn: sqlite3.Connection, vault: Vault, netflix: str
) -> None:
    invite = vault.create_share(netflix, ShareOptions(with_pin=True), pin_params=FAST)
    assert invite.pin is not None
    dump = "\n".join(conn.iterdump()).upper()  # blobs are dumped as X'HEX'
    assert invite.secret.hex().upper() not in dump
    assert invite.pin.encode().hex().upper() not in dump
    assert b"hunter2-netflix".hex().upper() not in dump
    assert "HUNTER2-NETFLIX" not in dump


def test_use_limit(conn: sqlite3.Connection, vault: Vault, netflix: str, clock: FakeClock) -> None:
    invite = vault.create_share(netflix, ShareOptions(max_uses=2), pin_params=FAST)
    token = _token(invite, None).lookup_token
    svc = ShareService(conn, clock)
    assert svc.redeem(invite.share_id, token).status is RedeemStatus.OK
    assert svc.redeem(invite.share_id, token).status is RedeemStatus.OK
    assert svc.redeem(invite.share_id, token).status is RedeemStatus.ENDED
    assert vault.list_shares()[0].status == "used"


def test_three_wrong_pins_expire_the_share_for_good(
    conn: sqlite3.Connection, vault: Vault, netflix: str, clock: FakeClock
) -> None:
    invite = vault.create_share(netflix, ShareOptions(with_pin=True), pin_params=FAST)
    assert invite.pin is not None
    wrong = "ZZZZZZ" if invite.pin != "ZZZZZZ" else "YYYYYY"
    svc = ShareService(conn, clock)

    first = svc.redeem(invite.share_id, _token(invite, wrong).lookup_token)
    second = svc.redeem(invite.share_id, _token(invite, wrong).lookup_token)
    third = svc.redeem(invite.share_id, _token(invite, wrong).lookup_token)

    assert (first.status, first.attempts_left) == (RedeemStatus.WRONG_TOKEN, 2)
    assert (second.status, second.attempts_left) == (RedeemStatus.WRONG_TOKEN, 1)
    assert third.status is RedeemStatus.EXPIRED_NOW

    # The right PIN no longer works, and the blob is gone.
    right = svc.redeem(invite.share_id, _token(invite, invite.pin).lookup_token)
    assert right.status is RedeemStatus.ENDED
    row = conn.execute("SELECT status, blob FROM shares").fetchone()
    assert (row["status"], row["blob"]) == ("expired", None)

    events = [e.event for e in reversed(store.audit_recent(conn, 20))]
    assert events.count("share.pin_failed") == 3
    assert "share.expired" in events


def test_pin_is_case_and_dash_insensitive(
    conn: sqlite3.Connection, vault: Vault, netflix: str, clock: FakeClock
) -> None:
    invite = vault.create_share(netflix, ShareOptions(with_pin=True), pin_params=FAST)
    assert invite.pin is not None
    typed = f"{invite.pin[:3].lower()}-{invite.pin[3:].lower()}"
    token = _token(invite, typed).lookup_token
    result = ShareService(conn, clock).redeem(invite.share_id, token)
    assert result.status is RedeemStatus.OK


def test_time_expiry(
    conn: sqlite3.Connection, vault: Vault, netflix: str, clock: FakeClock
) -> None:
    invite = vault.create_share(netflix, ShareOptions(ttl_seconds=60), pin_params=FAST)
    svc = ShareService(conn, clock)
    assert svc.info(invite.share_id).active
    clock.advance(61)
    assert not svc.info(invite.share_id).active
    token = _token(invite, None).lookup_token
    assert svc.redeem(invite.share_id, token).status is RedeemStatus.ENDED
    assert vault.list_shares()[0].status == "expired"


def test_time_expired_blob_is_deleted_without_a_redeem(
    conn: sqlite3.Connection, vault: Vault, netflix: str, clock: FakeClock
) -> None:
    vault.create_share(netflix, ShareOptions(ttl_seconds=60), pin_params=FAST)
    clock.advance(61)
    assert vault.list_shares()[0].status == "expired"
    assert conn.execute("SELECT blob FROM shares").fetchone()["blob"] is None


def test_revoke(conn: sqlite3.Connection, vault: Vault, netflix: str, clock: FakeClock) -> None:
    invite = vault.create_share(netflix, pin_params=FAST)
    vault.revoke_share(invite.share_id)
    token = _token(invite, None).lookup_token
    assert ShareService(conn, clock).redeem(invite.share_id, token).status is RedeemStatus.ENDED
    with pytest.raises(ShareNotFound):
        vault.revoke_share(invite.share_id)


def test_unknown_share_looks_like_ended(conn: sqlite3.Connection, clock: FakeClock) -> None:
    result = ShareService(conn, clock).redeem(crypto.b64e(bytes(16)), bytes(32))
    assert result.status is RedeemStatus.ENDED

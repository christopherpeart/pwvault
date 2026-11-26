"""End-to-end tests through the HTTP API, using the real clients."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import MASTER, FakeClock
from fastapi.testclient import TestClient

from pwvault import crypto, store
from pwvault.client import ClientError, RemoteVault, redeem_share
from pwvault.entries import EntryMeta, EntrySecret, derive_owner_keys
from pwvault.server import create_app
from pwvault.vault import ShareOptions, Vault

FAST = crypto.TEST_KDF


@pytest.fixture
def setup(tmp_path: Path, clock: FakeClock) -> Iterator[tuple[TestClient, Vault, str]]:
    db = tmp_path / "vault.db"
    conn = store.connect(db)
    vault = Vault.create(conn, MASTER, params=FAST, auth_params=FAST, clock=clock)
    netflix = vault.add(EntryMeta("Netflix", "me@example.com"), EntrySecret("hunter2-netflix"))
    vault.add(EntryMeta("Bank"), EntrySecret("bank-password"))
    with TestClient(create_app(db, clock=clock)) as http:
        yield http, vault, netflix
    conn.close()


def test_owner_lists_and_fetches_with_master_password(setup: tuple) -> None:  # type: ignore[type-arg]
    http, _, netflix = setup
    remote = RemoteVault("http://testserver", http=http, min_kdf=FAST)
    remote.login(MASTER)
    assert [m.name for _, m in remote.list_entries()] == ["Bank", "Netflix"]
    assert remote.get(netflix)[1].password == "hunter2-netflix"
    remote.logout()
    with pytest.raises(ClientError):
        remote.list_entries()


def test_account_endpoints_need_a_session(setup: tuple) -> None:  # type: ignore[type-arg]
    http, _, netflix = setup
    assert http.get("/v1/accounts").status_code == 401
    assert http.get(f"/v1/accounts/{netflix}").status_code == 401
    assert http.get("/v1/audit").status_code == 401
    bad = {"Authorization": "Bearer " + crypto.b64e(bytes(32))}
    assert http.get("/v1/accounts", headers=bad).status_code == 401


def test_wrong_master_password_is_refused(setup: tuple) -> None:  # type: ignore[type-arg]
    http, _, _ = setup
    with pytest.raises(ClientError, match="wrong master password"):
        RemoteVault("http://testserver", http=http, min_kdf=FAST).login("not the password")


def test_client_refuses_weak_kdf_settings_from_server(setup: tuple) -> None:  # type: ignore[type-arg]
    # The test vault uses minimum settings, which a real client must not accept.
    http, _, _ = setup
    with pytest.raises(ClientError, match="unsafe"):
        RemoteVault("http://testserver", http=http).login(MASTER)
    assert http.get("/v1/audit").status_code == 401  # and no login was attempted


def test_chunked_body_over_limit_is_rejected(setup: tuple) -> None:  # type: ignore[type-arg]
    http, _, _ = setup
    chunks = (b'{"auth": "' + b"A" * 1024 for _ in range(100))  # no Content-Length
    assert http.post("/v1/login", content=chunks).status_code == 413


def test_malformed_share_ids_are_not_logged(setup: tuple) -> None:  # type: ignore[type-arg]
    http, vault, _ = setup
    token = {"token": crypto.b64e(bytes(32))}
    assert http.post("/v1/shares/%1b%5b31mevil/redeem", json=token).status_code == 410
    assert http.post(f"/v1/shares/{crypto.b64e(bytes(16))}/redeem", json=token).status_code == 410
    assert not http.get("/v1/shares/x/info").json()["active"]
    events = [e.event for e in store.audit_recent(vault._conn, 50)]
    assert not any(e.startswith("share.redeem") for e in events)


def test_recipient_redeems_with_pin_and_sees_one_account(setup: tuple) -> None:  # type: ignore[type-arg]
    http, vault, netflix = setup
    invite = vault.create_share(netflix, ShareOptions(with_pin=True), pin_params=FAST)
    url = invite.url("http://testserver")

    shared = redeem_share(url, invite.pin, http=http, pin_params=FAST)

    assert (shared.name, shared.password) == ("Netflix", "hunter2-netflix")
    # One use: the link is now dead, and share tokens never open account endpoints.
    with pytest.raises(ClientError, match="ended"):
        redeem_share(url, invite.pin, http=http, pin_params=FAST)


def test_three_wrong_pins_over_http_expire_the_share(setup: tuple) -> None:  # type: ignore[type-arg]
    http, vault, netflix = setup
    invite = vault.create_share(netflix, ShareOptions(with_pin=True), pin_params=FAST)
    url = invite.url("http://testserver")
    wrong = "ZZZZZZ" if invite.pin != "ZZZZZZ" else "YYYYYY"

    with pytest.raises(ClientError, match="2 attempts left"):
        redeem_share(url, wrong, http=http, pin_params=FAST)
    with pytest.raises(ClientError, match="1 attempt left"):
        redeem_share(url, wrong, http=http, pin_params=FAST)
    with pytest.raises(ClientError, match="expired"):
        redeem_share(url, wrong, http=http, pin_params=FAST)
    with pytest.raises(ClientError, match="ended"):
        redeem_share(url, invite.pin, http=http, pin_params=FAST)


def test_owner_management_is_not_exposed_over_http(setup: tuple) -> None:  # type: ignore[type-arg]
    http, _, netflix = setup
    token = http.post("/v1/login", json={"auth": _auth(http)}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    # Editing and sharing happen only through the CLI on the owner's machine.
    assert http.put(f"/v1/accounts/{netflix}", headers=headers, json={}).status_code == 405
    assert http.post("/v1/shares", headers=headers, json={}).status_code in (404, 405)


def test_security_headers_and_redeem_page(setup: tuple) -> None:  # type: ignore[type-arg]
    http, _, _ = setup
    page = http.get("/s/" + crypto.b64e(bytes(16)))
    assert page.status_code == 200 and "Shared password" in page.text
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert http.get("/static/redeem.js").status_code == 200


def test_audit_log_records_failures(setup: tuple) -> None:  # type: ignore[type-arg]
    http, _, _ = setup
    http.post("/v1/login", json={"auth": crypto.b64e(bytes(32))})
    token = http.post("/v1/login", json={"auth": _auth(http)}).json()["token"]
    events = http.get("/v1/audit", headers={"Authorization": f"Bearer {token}"}).json()["events"]
    names = [e["event"] for e in events]
    assert "login.failed" in names and "login.ok" in names


def _auth(http: TestClient) -> str:
    """The auth key a client would send, derived via the public prelogin data."""
    pre = http.get("/v1/prelogin").json()
    params = crypto.KdfParams(pre["opslimit"], pre["memlimit"])
    return crypto.b64e(derive_owner_keys(MASTER, crypto.b64d(pre["salt"]), params)[1])

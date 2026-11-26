from __future__ import annotations

import sqlite3

from conftest import MASTER, FakeClock

from pwvault import store
from pwvault.entries import derive_owner_keys
from pwvault.services import (
    LOGIN_MAX_FAILURES,
    SESSION_IDLE_SECONDS,
    AuthService,
    LoginStatus,
)
from pwvault.vault import Vault


def _auth_key(conn: sqlite3.Connection, password: str) -> bytes:
    settings = store.load_kdf_settings(conn)
    assert settings is not None
    return derive_owner_keys(password, *settings)[1]


def test_login_with_master_password(
    conn: sqlite3.Connection, vault: Vault, clock: FakeClock
) -> None:
    svc = AuthService(conn, clock)
    result = svc.login(_auth_key(conn,MASTER))
    assert result.status is LoginStatus.OK and result.token
    assert svc.validate(result.token)
    assert not svc.validate("not-a-token")


def test_five_failures_lock_login_and_lock_doubles(
    conn: sqlite3.Connection, vault: Vault, clock: FakeClock
) -> None:
    svc = AuthService(conn, clock)
    wrong, right = _auth_key(conn,"wrong password"), _auth_key(conn,MASTER)

    results = [svc.login(wrong) for _ in range(LOGIN_MAX_FAILURES)]
    assert [r.status for r in results[:-1]] == [LoginStatus.WRONG] * (LOGIN_MAX_FAILURES - 1)
    assert results[-1].status is LoginStatus.LOCKED
    assert results[-1].locked_until == clock.now + 15 * 60

    # Even the right password is refused while locked.
    assert svc.login(right).status is LoginStatus.LOCKED

    clock.advance(15 * 60)
    for _ in range(LOGIN_MAX_FAILURES):
        last = svc.login(wrong)
    assert last.locked_until == clock.now + 30 * 60  # doubled

    events = [e.event for e in store.audit_recent(conn, 100)]
    assert events.count("login.failed") == 2 * LOGIN_MAX_FAILURES
    assert events.count("login.locked") == 2


def test_success_resets_failure_count(
    conn: sqlite3.Connection, vault: Vault, clock: FakeClock
) -> None:
    svc = AuthService(conn, clock)
    wrong, right = _auth_key(conn,"wrong password"), _auth_key(conn,MASTER)
    for _ in range(LOGIN_MAX_FAILURES - 1):
        svc.login(wrong)
    assert svc.login(right).status is LoginStatus.OK
    assert svc.login(wrong).status is LoginStatus.WRONG  # count started again


def test_session_expires_when_idle(
    conn: sqlite3.Connection, vault: Vault, clock: FakeClock
) -> None:
    svc = AuthService(conn, clock)
    token = svc.login(_auth_key(conn,MASTER)).token
    assert token is not None
    clock.advance(SESSION_IDLE_SECONDS - 1)
    assert svc.validate(token)  # use refreshes the idle timer
    clock.advance(SESSION_IDLE_SECONDS - 1)
    assert svc.validate(token)
    clock.advance(SESSION_IDLE_SECONDS + 1)
    assert not svc.validate(token)
    svc.logout(token)

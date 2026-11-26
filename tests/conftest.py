from __future__ import annotations

import sqlite3
from collections.abc import Iterator

import pytest

from pwvault import crypto, store
from pwvault.entries import EntryMeta, EntrySecret
from pwvault.vault import Vault

MASTER = "correct horse battery staple"


class FakeClock:
    """Manually advanced clock, so tests can expire shares and sessions."""

    def __init__(self, start: int = 1_800_000_000) -> None:
        self.now = start

    def __call__(self) -> int:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = store.connect(":memory:")
    yield c
    c.close()


@pytest.fixture
def vault(conn: sqlite3.Connection, clock: FakeClock) -> Vault:
    return Vault.create(
        conn, MASTER, params=crypto.TEST_KDF, auth_params=crypto.TEST_KDF, clock=clock
    )


@pytest.fixture
def netflix(vault: Vault) -> str:
    return vault.add(
        EntryMeta(name="Netflix", username="me@example.com", url="https://netflix.com"),
        EntrySecret(password="hunter2-netflix", notes="family plan"),
    )

"""Encryption of vault entries and the owner keys derived from the master password.

Used by the local vault and by the remote client, which receives the same
ciphertext from the server and decrypts it with a vault key it derived itself.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from pwvault import crypto


@dataclass
class EntryMeta:
    name: str
    username: str = ""
    url: str = ""


@dataclass
class EntrySecret:
    password: str
    notes: str = ""


@dataclass
class EncryptedEntry:
    id: str
    version: int
    wrapped_key: bytes  # entry key under the vault key
    meta_ct: bytes  # EntryMeta under the entry key
    secret_ct: bytes  # EntrySecret under the entry key


def _ad(kind: str, entry_id: str, version: int) -> bytes:
    # The ID and version are bound in as associated data, so ciphertext can't be
    # moved to another entry or rolled back to an older version undetected.
    return f"pwvault/{kind}/v1|{entry_id}|{version}".encode()


def _dump(obj: object) -> bytes:
    return json.dumps(asdict(obj), separators=(",", ":")).encode()  # type: ignore[call-overload]


def seal_entry(
    vault_key: bytes, entry_id: str, version: int, meta: EntryMeta, secret: EntrySecret
) -> EncryptedEntry:
    """Encrypts an entry under a fresh entry key, wrapped by the vault key."""
    entry_key = crypto.random_bytes(crypto.KEY_SIZE)
    return EncryptedEntry(
        id=entry_id,
        version=version,
        wrapped_key=crypto.aead_encrypt(vault_key, entry_key, _ad("entry-key", entry_id, version)),
        meta_ct=crypto.aead_encrypt(entry_key, _dump(meta), _ad("entry-meta", entry_id, version)),
        secret_ct=crypto.aead_encrypt(
            entry_key, _dump(secret), _ad("entry-secret", entry_id, version)
        ),
    )


def _entry_key(vault_key: bytes, entry: EncryptedEntry) -> bytes:
    return crypto.aead_decrypt(
        vault_key, entry.wrapped_key, _ad("entry-key", entry.id, entry.version)
    )


def open_meta(vault_key: bytes, entry: EncryptedEntry) -> EntryMeta:
    key = _entry_key(vault_key, entry)
    data = crypto.aead_decrypt(key, entry.meta_ct, _ad("entry-meta", entry.id, entry.version))
    return EntryMeta(**json.loads(data))


def open_secret(vault_key: bytes, entry: EncryptedEntry) -> EntrySecret:
    key = _entry_key(vault_key, entry)
    data = crypto.aead_decrypt(
        key, entry.secret_ct, _ad("entry-secret", entry.id, entry.version)
    )
    return EntrySecret(**json.loads(data))


def derive_owner_keys(
    master_password: str, salt: bytes, params: crypto.KdfParams
) -> tuple[bytes, bytes]:
    """Master password -> (vault key, auth key).

    The vault key decrypts entries and never leaves the client. The auth key
    only proves knowledge of the master password; it cannot decrypt anything.
    """
    vault_key = crypto.argon2id(master_password.encode("utf-8"), salt, params)
    return vault_key, crypto.hkdf_sha256(vault_key, b"pwvault/auth/v1", b"auth")


def new_id() -> str:
    """Random 16-byte ID, base64url encoded (22 characters)."""
    return crypto.b64e(crypto.random_bytes(16))

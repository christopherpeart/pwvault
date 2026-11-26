"""Share keys, PINs and links.

A share is one entry encrypted under a key derived from a 128-bit share secret
(carried only in the QR code / link fragment) plus an optional 6-character PIN
(sent to the recipient separately). The server sees neither; it only stores
SHA-256 of the lookup token, so it can count wrong PINs without knowing them.

Everything here must stay byte-for-byte compatible with web/redeem.js.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

from pwvault import crypto

# 31 characters: digits and letters without look-alikes (0/O, 1/I/L).
PIN_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
PIN_LENGTH = 6
SECRET_SIZE = 16  # 128 bits
_HKDF_SALT = b"pwvault/share/v1"


def generate_pin() -> str:
    return "".join(secrets.choice(PIN_ALPHABET) for _ in range(PIN_LENGTH))


def normalize_pin(pin: str) -> str:
    """Accepts lower case, spaces and dashes ("ab3-k9m")."""
    return "".join(ch for ch in pin if ch not in " -").upper()


@dataclass(frozen=True)
class ShareKeys:
    enc_key: bytes
    lookup_token: bytes


def derive_share_keys(
    share_id: str,
    secret: bytes,
    pin: str | None,
    pin_params: crypto.KdfParams = crypto.PIN_KDF,
) -> ShareKeys:
    ikm = secret
    if pin:
        # The share ID's 16 raw bytes double as the Argon2id salt.
        pin_key = crypto.argon2id(normalize_pin(pin).encode(), crypto.b64d(share_id), pin_params)
        ikm = secret + pin_key
    return ShareKeys(
        enc_key=crypto.hkdf_sha256(ikm, _HKDF_SALT, f"enc|{share_id}".encode()),
        lookup_token=crypto.hkdf_sha256(ikm, _HKDF_SALT, f"lookup|{share_id}".encode()),
    )


def _blob_ad(share_id: str) -> bytes:
    return f"pwvault/share-blob/v1|{share_id}".encode()


@dataclass
class SharedEntry:
    """What a recipient sees: one account, nothing else."""

    name: str
    username: str
    password: str


def seal_share_payload(enc_key: bytes, share_id: str, entry: SharedEntry) -> bytes:
    data = json.dumps(
        {"name": entry.name, "username": entry.username, "password": entry.password},
        separators=(",", ":"),
    ).encode()
    return crypto.aead_encrypt(enc_key, data, _blob_ad(share_id))


def open_share_payload(enc_key: bytes, share_id: str, blob: bytes) -> SharedEntry:
    data = json.loads(crypto.aead_decrypt(enc_key, blob, _blob_ad(share_id)))
    return SharedEntry(name=data["name"], username=data["username"], password=data["password"])


def format_share_url(base_url: str, share_id: str, secret: bytes) -> str:
    # The secret sits in the URL fragment, which browsers never send to a server.
    return f"{base_url.rstrip('/')}/s/{share_id}#{crypto.b64e(secret)}"


@dataclass(frozen=True)
class ParsedShareUrl:
    base_url: str
    share_id: str
    secret: bytes


def parse_share_url(url: str) -> ParsedShareUrl:
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    marker = path.rfind("/s/")
    if not parts.scheme or not parts.netloc or marker < 0 or not parts.fragment:
        raise ValueError("not a share link (expected https://host/s/<id>#<secret>)")
    share_id = path[marker + 3 :]
    secret = crypto.b64d(parts.fragment)
    if len(crypto.b64d(share_id)) != 16 or len(secret) != SECRET_SIZE:
        raise ValueError("share link is malformed")
    base = f"{parts.scheme}://{parts.netloc}{path[:marker]}"
    return ParsedShareUrl(base_url=base, share_id=share_id, secret=secret)

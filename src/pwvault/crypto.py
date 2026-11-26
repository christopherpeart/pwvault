"""Thin wrappers over libsodium (via PyNaCl) and the standard library.

Every primitive choice in the project lives here, so the rest of the code
never calls PyNaCl directly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

import nacl.bindings as sodium
import nacl.exceptions
import nacl.pwhash

KEY_SIZE = 32
SALT_SIZE = nacl.pwhash.argon2id.SALTBYTES  # 16
NONCE_SIZE = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24
TAG_SIZE = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES  # 16


class CryptoError(Exception):
    """Something went wrong in a cryptographic operation."""


class DecryptError(CryptoError):
    """Authentication failed: wrong key, wrong associated data, or tampering."""


@dataclass(frozen=True)
class KdfParams:
    opslimit: int
    memlimit: int  # bytes


_MIB = 1024 * 1024

# Argon2id settings from the design spec.
MASTER_KDF = KdfParams(opslimit=3, memlimit=256 * _MIB)  # about 1 s
PIN_KDF = KdfParams(opslimit=3, memlimit=64 * _MIB)  # fixed: the redeem page must match
AUTH_HASH_KDF = KdfParams(opslimit=2, memlimit=64 * _MIB)  # server-side hash of the auth key
# Minimum settings. Only for unit tests: far too weak for real use.
TEST_KDF = KdfParams(
    opslimit=nacl.pwhash.argon2id.OPSLIMIT_MIN, memlimit=nacl.pwhash.argon2id.MEMLIMIT_MIN
)


def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def argon2id(password: bytes, salt: bytes, params: KdfParams) -> bytes:
    """Argon2id(password, salt) -> 32-byte key."""
    if len(salt) != SALT_SIZE:
        raise CryptoError(f"Argon2id salt must be {SALT_SIZE} bytes")
    return bytes(
        nacl.pwhash.argon2id.kdf(
            KEY_SIZE, password, salt, opslimit=params.opslimit, memlimit=params.memlimit
        )
    )


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_SIZE) -> bytes:
    """RFC 5869 HKDF with SHA-256. Matches WebCrypto's HKDF, used by the redeem page."""
    if length > 255 * 32:
        raise CryptoError("HKDF output too long")
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def aead_encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """XChaCha20-Poly1305. Output layout: nonce (24) || ciphertext || tag (16)."""
    nonce = random_bytes(NONCE_SIZE)
    sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, associated_data, nonce, key
    )
    return nonce + bytes(sealed)


def aead_decrypt(key: bytes, sealed: bytes, associated_data: bytes) -> bytes:
    if len(sealed) < NONCE_SIZE + TAG_SIZE:
        raise DecryptError("ciphertext too short")
    nonce, ciphertext = sealed[:NONCE_SIZE], sealed[NONCE_SIZE:]
    try:
        return bytes(
            sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext, associated_data, nonce, key
            )
        )
    except nacl.exceptions.CryptoError as exc:
        raise DecryptError("decryption failed: wrong key or data was modified") from exc


def hash_for_storage(secret: bytes, params: KdfParams) -> bytes:
    """Self-describing Argon2id hash ($argon2id$...) for verifying a secret later."""
    return bytes(
        nacl.pwhash.argon2id.str(secret, opslimit=params.opslimit, memlimit=params.memlimit)
    )


def verify_stored_hash(stored: bytes, secret: bytes) -> bool:
    try:
        return bool(nacl.pwhash.verify(stored, secret))
    except nacl.exceptions.InvalidkeyError:
        return False


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def b64e(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    """Strict base64url decode (no padding, no stray characters)."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise CryptoError("invalid base64url data")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

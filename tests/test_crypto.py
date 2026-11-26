from __future__ import annotations

import pytest

from pwvault import crypto


def test_hkdf_matches_rfc5869_test_case_1() -> None:
    ikm = bytes([0x0B] * 22)
    salt = bytes(range(0x00, 0x0D))
    info = bytes(range(0xF0, 0xFA))
    okm = crypto.hkdf_sha256(ikm, salt, info, length=42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_aead_round_trip() -> None:
    key = crypto.random_bytes(32)
    sealed = crypto.aead_encrypt(key, b"secret", b"ad")
    assert crypto.aead_decrypt(key, sealed, b"ad") == b"secret"


def test_aead_uses_fresh_nonces() -> None:
    key = crypto.random_bytes(32)
    assert crypto.aead_encrypt(key, b"x", b"") != crypto.aead_encrypt(key, b"x", b"")


@pytest.mark.parametrize("position", [0, 30, -1])  # nonce, ciphertext, tag
def test_aead_rejects_any_modified_byte(position: int) -> None:
    key = crypto.random_bytes(32)
    sealed = bytearray(crypto.aead_encrypt(key, b"some plaintext", b"ad"))
    sealed[position] ^= 0x01
    with pytest.raises(crypto.DecryptError):
        crypto.aead_decrypt(key, bytes(sealed), b"ad")


def test_aead_rejects_wrong_associated_data_or_key() -> None:
    key = crypto.random_bytes(32)
    sealed = crypto.aead_encrypt(key, b"x", b"entry-1")
    with pytest.raises(crypto.DecryptError):
        crypto.aead_decrypt(key, sealed, b"entry-2")
    with pytest.raises(crypto.DecryptError):
        crypto.aead_decrypt(crypto.random_bytes(32), sealed, b"entry-1")


def test_stored_hash_verifies_only_the_same_secret() -> None:
    stored = crypto.hash_for_storage(b"auth-key", crypto.TEST_KDF)
    assert stored.startswith(b"$argon2id$")
    assert crypto.verify_stored_hash(stored, b"auth-key")
    assert not crypto.verify_stored_hash(stored, b"other")


def test_argon2id_is_deterministic_and_salted() -> None:
    salt = bytes(16)
    a = crypto.argon2id(b"pw", salt, crypto.TEST_KDF)
    assert a == crypto.argon2id(b"pw", salt, crypto.TEST_KDF)
    assert a != crypto.argon2id(b"pw", bytes([1] * 16), crypto.TEST_KDF)
    with pytest.raises(crypto.CryptoError):
        crypto.argon2id(b"pw", b"short", crypto.TEST_KDF)


@pytest.mark.parametrize("data", [b"", b"\x00", b"\xff" * 17, bytes(range(256))])
def test_b64url_round_trip(data: bytes) -> None:
    text = crypto.b64e(data)
    assert "=" not in text and "+" not in text and "/" not in text
    assert crypto.b64d(text) == data


@pytest.mark.parametrize("bad", ["a", "ab+c", "ab/c", "abc=", "ab c"])
def test_b64url_rejects_bad_input(bad: str) -> None:
    with pytest.raises(crypto.CryptoError):
        crypto.b64d(bad)

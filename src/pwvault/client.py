"""HTTP clients: the owner's remote access, and share redemption for recipients.

The master password and vault key never leave this process. The server only
ever receives the auth key (which cannot decrypt anything) and lookup tokens.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from pwvault import crypto, shares
from pwvault.entries import (
    EncryptedEntry,
    EntryMeta,
    EntrySecret,
    derive_owner_keys,
    open_meta,
    open_secret,
)


class ClientError(Exception):
    pass


def _detail(response: httpx.Response) -> str:
    try:
        return str(response.json().get("detail", response.text))
    except ValueError:
        return response.text or f"HTTP {response.status_code}"


_MAX_KDF = crypto.KdfParams(opslimit=20, memlimit=4096 * 1024 * 1024)


class RemoteVault:
    """Owner access to the vault through the server, gated by the master password.

    The server supplies the Argon2id settings, so the client refuses anything
    weaker than `min_kdf`. Otherwise a fake or hijacked server could ask for
    cheap settings and then guess the master password from the auth key it gets.
    """

    def __init__(
        self,
        base_url: str,
        http: httpx.Client | None = None,
        *,
        min_kdf: crypto.KdfParams = crypto.MASTER_KDF,
    ) -> None:
        self._http = http or httpx.Client(base_url=base_url.rstrip("/"), timeout=30)
        self._min_kdf = min_kdf
        self._token: str | None = None
        self._key: bytes | None = None

    def login(self, master_password: str) -> None:
        pre = self._http.get("/v1/prelogin")
        if pre.status_code != 200:
            raise ClientError(f"prelogin failed: {_detail(pre)}")
        info = pre.json()
        params = crypto.KdfParams(opslimit=int(info["opslimit"]), memlimit=int(info["memlimit"]))
        if not (self._min_kdf.opslimit <= params.opslimit <= _MAX_KDF.opslimit
                and self._min_kdf.memlimit <= params.memlimit <= _MAX_KDF.memlimit):
            raise ClientError(
                "the server asked for unsafe key-derivation settings; not sending a login"
            )
        vault_key, auth_key = derive_owner_keys(master_password, crypto.b64d(info["salt"]), params)
        resp = self._http.post("/v1/login", json={"auth": crypto.b64e(auth_key)})
        if resp.status_code == 423:
            raise ClientError(f"login locked until {resp.json().get('locked_until')}")
        if resp.status_code != 200:
            raise ClientError(f"login failed: {_detail(resp)}")
        self._token = resp.json()["token"]
        self._key = vault_key

    def logout(self) -> None:
        if self._token:
            self._http.post("/v1/logout", headers=self._headers())
        self._token = None
        self._key = None

    def list_entries(self) -> list[tuple[str, EntryMeta]]:
        data = self._get("/v1/accounts")
        items = []
        for row in data["accounts"]:
            entry = EncryptedEntry(
                row["id"], row["version"], crypto.b64d(row["wrapped_key"]),
                crypto.b64d(row["meta_ct"]), b"",
            )
            items.append((row["id"], open_meta(self._vault_key(), entry)))
        return sorted(items, key=lambda item: item[1].name.lower())

    def get(self, entry_id: str) -> tuple[EntryMeta, EntrySecret]:
        row = self._get(f"/v1/accounts/{entry_id}")
        entry = EncryptedEntry(
            row["id"], row["version"], crypto.b64d(row["wrapped_key"]),
            crypto.b64d(row["meta_ct"]), crypto.b64d(row["secret_ct"]),
        )
        return open_meta(self._vault_key(), entry), open_secret(self._vault_key(), entry)

    def _get(self, path: str) -> Any:
        resp = self._http.get(path, headers=self._headers())
        if resp.status_code != 200:
            raise ClientError(f"request failed: {_detail(resp)}")
        return resp.json()

    def _headers(self) -> dict[str, str]:
        if not self._token:
            raise ClientError("not logged in")
        return {"Authorization": f"Bearer {self._token}"}

    def _vault_key(self) -> bytes:
        if self._key is None:
            raise ClientError("not logged in")
        return self._key


def redeem_share(
    url: str,
    pin: str | Callable[[], str] | None = None,
    *,
    http: httpx.Client | None = None,
    pin_params: crypto.KdfParams = crypto.PIN_KDF,
) -> shares.SharedEntry:
    """Redeems a share link. `pin` may be a string or a callable that prompts for it.

    Raises ClientError with a readable message if the share has ended or the
    PIN is wrong. Each wrong PIN uses up one of the three attempts.
    """
    link = shares.parse_share_url(url)
    client = http or httpx.Client(base_url=link.base_url, timeout=30)

    info = client.get(f"/v1/shares/{link.share_id}/info").json()
    if not info.get("active"):
        raise ClientError("this share has ended")
    pin_value: str | None = None
    if info.get("has_pin"):
        pin_value = pin() if callable(pin) else pin
        if not pin_value:
            raise ClientError("this share needs a PIN")

    keys = shares.derive_share_keys(link.share_id, link.secret, pin_value, pin_params)
    resp = client.post(
        f"/v1/shares/{link.share_id}/redeem", json={"token": crypto.b64e(keys.lookup_token)}
    )
    if resp.status_code == 403:
        left = resp.json().get("attempts_left")
        raise ClientError(f"wrong PIN ({left} attempt{'s' if left != 1 else ''} left)")
    if resp.status_code != 200:
        raise ClientError(_detail(resp))
    return shares.open_share_payload(keys.enc_key, link.share_id, crypto.b64d(resp.json()["blob"]))

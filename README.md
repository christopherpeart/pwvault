# pwvault

A self-hosted password vault that can share **one** account's password through a
QR code, without the server ever being able to read it.

- **Local encrypted vault.** Unlocked with a master password (Argon2id, 256 MiB) and
  encrypted per entry with XChaCha20-Poly1305.
- **Self-hosted only.** The server runs on your machine behind your own reverse proxy.
  It stores only ciphertext and hashes.
- **Remote access needs the master password.** The password never crosses the
  network. Clients send a derived *auth key* that can't decrypt anything.
- **QR-code sharing.** Each share covers one account, has an expiry and a use limit,
  and can require a random 6-character PIN. **Three wrong PINs expire the share for
  good.**
- **Recipients see only the shared password,** never the account list.
- **Changing a password ends every active share** for that account.
- **Audit log.** Logins, failed logins, redemptions, wrong PINs and expired shares
  are all recorded. Nothing sends alerts.

The full design and threat model is in the design spec.

## How sharing works

```
owner's CLI ── share secret (QR) + PIN (separately) ──▶ recipient
     │                                                     │
     │ encrypted blob + SHA-256(lookup token)              │ lookup token
     ▼                                                     ▼
            local server (ciphertext only) ◀── reverse proxy (TLS)
```

1. `pwvault share Netflix --pin` encrypts that one entry under a key derived from a
   random 128-bit secret and the PIN: `HKDF(secret ‖ Argon2id(PIN))`.
2. The secret is placed only in the link's `#fragment`, which browsers never send to
   a server. The PIN goes to the recipient through a different channel.
3. The recipient derives a *lookup token* from both. The server compares
   `SHA-256(token)` to what it stored. This lets it count wrong PINs without ever
   seeing the PIN.
4. On a match, the server returns the blob, and the recipient decrypts it locally.

## Setup

Requires Python 3.11+. Run these from the `pwvault` folder (the one with
`pyproject.toml`). They call the venv's Python directly, so they work without
activating it and in any Windows shell. Use `py` instead of `python` if
`python` isn't found.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest
```

On macOS or Linux, use `.venv/bin/python` instead of `.venv\Scripts\python`.

To put `pwvault`, `pytest` and `pip` on your PATH for the session, activate the venv.
The command depends on the shell:

| Shell | Activate |
| --- | --- |
| PowerShell | `.venv\Scripts\Activate.ps1` |
| Command Prompt (cmd) | `.venv\Scripts\activate.bat` |
| Git Bash | `source .venv/Scripts/activate` |
| macOS / Linux | `source .venv/bin/activate` |

If PowerShell says "running scripts is disabled on this system", allow local
scripts for your user once, then try again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Or skip activation and run `.venv\Scripts\pwvault` directly.

### The browser redeem page

Recipients can open share links in a browser. The page decrypts with
[libsodium.js](https://github.com/jedisct1/libsodium.js). Download the **sumo**
browser build (`dist/browsers-sumo/sodium.js`) and save it as
`src/pwvault/web/sodium.js`. It's served from your own server rather than a CDN,
so a third party can't swap the code that sees the password. Recipients can also
use the CLI: `pwvault redeem <link>`.

## Usage

These assume the venv is activated. Otherwise, write `.venv\Scripts\pwvault`
instead of `pwvault`.

```powershell
pwvault init                               # create the vault
pwvault add                                # prompts for name, username, password ('g' generates)
pwvault list
pwvault get netflix
pwvault edit netflix                       # a new password ends all of its shares

pwvault set-url https://vault.example.com  # public URL your reverse proxy serves
pwvault share netflix --pin --ttl 24h --uses 1 --qr-svg netflix.svg
pwvault shares                             # status of every share
pwvault revoke <share-id>
pwvault audit

pwvault serve --port 8787                  # point the reverse proxy at 127.0.0.1:8787
pwvault remote https://vault.example.com list
pwvault redeem "https://vault.example.com/s/<id>#<secret>"
```

The database defaults to `~/.pwvault/vault.db`. Override it with `--db` or `PWVAULT_DB`.

### Reverse proxy

The server listens on `127.0.0.1` over plain HTTP. Your proxy (Caddy, nginx, IIS)
terminates TLS and forwards everything to it. The server ignores `X-Forwarded-*`
headers for security decisions, so all lockouts count per account and per share.
Forwarded addresses are written to the audit log, marked as unverified.

## Project layout

| File | Role |
| --- | --- |
| `crypto.py` | libsodium wrappers: Argon2id, HKDF, XChaCha20-Poly1305, base64url |
| `store.py` | SQLite schema, audit log, ending shares on password change |
| `entries.py` | Per-entry encryption; vault and auth key derivation |
| `vault.py` | Owner operations: unlock, add, edit, share, revoke |
| `shares.py` | PIN generation, share key derivation, links |
| `services.py` | Server rules: redemption limits, login lockout, sessions |
| `server.py` | FastAPI app and security headers |
| `client.py` | Remote owner access and share redemption |
| `cli.py` | `pwvault` command |
| `web/` | Browser redeem page |

## Security notes

- Python can't lock keys in memory or reliably wipe them, so keep auto-lock short
  and don't run this on a shared machine.
- A weak master password can still be guessed offline from a stolen database.
  Use a long passphrase.
- Anyone who sees a share link can use up its three PIN attempts. This is logged,
  and the owner creates a new share.
- Anyone who can reach the server can lock remote login by sending 5 wrong auth
  keys. Local CLI use is never locked.
- Pin libsodium.js to a release tag rather than `master`, and check its SHA-256
  when you update it: that file sees every shared password the browser decrypts.
- `pwvault remote` refuses servers that ask for weaker Argon2id settings than the
  defaults, so a fake server can't make the master password cheap to guess.

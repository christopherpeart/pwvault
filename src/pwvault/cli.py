"""Command-line interface: `pwvault <command>`. Run `pwvault -h` for the list."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import sqlite3
import string
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import httpx

from pwvault import __version__, client, crypto, store
from pwvault.entries import EntryMeta, EntrySecret
from pwvault.vault import ShareOptions, Vault, VaultError, is_initialized

DEFAULT_DB = Path(os.environ.get("PWVAULT_DB", Path.home() / ".pwvault" / "vault.db"))
DEFAULT_PORT = 8787


# ---- Helpers ----------------------------------------------------------------


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def _open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    conn = store.connect(path)
    if os.name == "posix":
        path.chmod(0o600)  # owner only; SQLite gives the -wal/-shm files the same mode
    return conn


def _printable(text: str) -> str:
    """Replaces control characters so logged text (which can come from
    unauthenticated requests) can't send escape codes to the terminal."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _unlock(conn: sqlite3.Connection) -> Vault:
    return Vault.unlock(conn, getpass.getpass("Master password: "))


def _when(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        # Require each character class so sites with composition rules accept it.
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or default


def _ask_password(current: str | None = None) -> str:
    hint = "Enter to keep current, " if current is not None else ""
    while True:
        pw = getpass.getpass(f"Password ({hint}'g' to generate): ")
        if not pw and current is not None:
            return current
        if pw == "g":
            pw = generate_password()
            print(f"Generated: {pw}")
            return pw
        if pw and getpass.getpass("Repeat password: ") == pw:
            return pw
        print("Passwords were empty or did not match; try again.")


_DURATION = re.compile(r"^(\d+)([smhd])$")


def parse_duration(text: str) -> int:
    match = _DURATION.match(text.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError("use a number plus s, m, h or d (for example 24h)")
    value, unit = int(match.group(1)), match.group(2)
    return value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def _print_qr(url: str, svg_path: str | None) -> None:
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        print("(install the 'qrcode' package to show a QR code)")
        return
    qr = qrcode.QRCode(border=2)
    qr.add_data(url)
    qr.make(fit=True)
    try:
        qr.print_ascii(invert=True)
    except UnicodeEncodeError:
        print("(this terminal can't draw the QR code; use --qr-svg FILE)")
    if svg_path:
        qr.make_image(image_factory=qrcode.image.svg.SvgPathImage).save(svg_path)
        print(f"QR code saved to {svg_path}")


# ---- Commands -----------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    conn = _open_db(args.db)
    if is_initialized(conn):
        return _fail(f"a vault already exists at {args.db}")
    pw = getpass.getpass("New master password (8+ characters): ")
    if getpass.getpass("Repeat master password: ") != pw:
        return _fail("passwords did not match")
    print("Deriving key (this takes about a second)...")
    Vault.create(conn, pw)
    print(f"Vault created at {args.db}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    vault = _unlock(_open_db(args.db))
    meta = EntryMeta(name=_ask("Name (e.g. Netflix)"), username=_ask("Username"),
                     url=_ask("URL"))
    if not meta.name:
        return _fail("a name is required")
    secret = EntrySecret(password=_ask_password(), notes=_ask("Notes"))
    entry_id = vault.add(meta, secret)
    print(f"Added {meta.name} ({entry_id})")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    vault = _unlock(_open_db(args.db))
    items = vault.list_entries()
    if not items:
        print("The vault is empty. Add an entry with `pwvault add`.")
    for entry_id, meta in items:
        print(f"{entry_id}  {meta.name:<24} {meta.username:<28} {meta.url}")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    vault = _unlock(_open_db(args.db))
    meta, secret = vault.get(vault.find(args.query))
    print(f"Name:     {meta.name}\nUsername: {meta.username}\nURL:      {meta.url}")
    print(f"Password: {secret.password}")
    if secret.notes:
        print(f"Notes:    {secret.notes}")
    return 0


def cmd_edit(args: argparse.Namespace) -> int:
    vault = _unlock(_open_db(args.db))
    entry_id = vault.find(args.query)
    meta, secret = vault.get(entry_id)
    new_meta = EntryMeta(name=_ask("Name", meta.name), username=_ask("Username", meta.username),
                         url=_ask("URL", meta.url))
    new_secret = EntrySecret(password=_ask_password(secret.password),
                             notes=_ask("Notes", secret.notes))
    ended = vault.update(entry_id, new_meta, new_secret)
    print(f"Updated {new_meta.name}.")
    if ended:
        print(f"The password changed, so {ended} active share(s) for it have ended.")
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    vault = _unlock(_open_db(args.db))
    entry_id = vault.find(args.query)
    meta, _ = vault.get(entry_id)
    if _ask(f"Delete {meta.name}? Type the name to confirm") != meta.name:
        return _fail("not deleted")
    ended = vault.remove(entry_id)
    print(f"Deleted {meta.name}" + (f"; {ended} share(s) ended." if ended else "."))
    return 0


def cmd_gen(args: argparse.Namespace) -> int:
    print(generate_password(args.length))
    return 0


def cmd_set_url(args: argparse.Namespace) -> int:
    conn = _open_db(args.db)
    store.meta_set(conn, "public_url", args.url.rstrip("/").encode())
    print(f"Share links will use {args.url.rstrip('/')}")
    return 0


def cmd_share(args: argparse.Namespace) -> int:
    conn = _open_db(args.db)
    base_url = args.base_url or (store.meta_get(conn, "public_url") or b"").decode()
    if not base_url:
        return _fail("set the public URL first: pwvault set-url https://vault.example.com")
    vault = _unlock(conn)
    entry_id = vault.find(args.query)
    meta, _ = vault.get(entry_id)
    invite = vault.create_share(
        entry_id, ShareOptions(ttl_seconds=args.ttl, max_uses=args.uses, with_pin=args.pin)
    )
    url = invite.url(base_url)
    print(f"\nShare for {meta.name}: {args.uses} use(s), expires {_when(invite.expires_at)}\n")
    _print_qr(url, args.qr_svg)
    print(f"\nLink: {url}")
    if invite.pin:
        print(f"PIN:  {invite.pin}   <- send this separately (text or call), not with the link")
        print("      3 wrong PINs expire the share for good.")
    print(f"Share ID: {invite.share_id}")
    return 0


def cmd_shares(args: argparse.Namespace) -> int:
    vault = _unlock(_open_db(args.db))
    names = {entry_id: meta.name for entry_id, meta in vault.list_entries()}
    rows = vault.list_shares()
    if not rows:
        print("No shares yet.")
    for s in rows:
        print(f"{s.id}  {names.get(s.entry_id, '(deleted)'):<20} {s.status:<8}"
              f" pin={'yes' if s.has_pin else 'no ':<3} uses_left={s.uses_left}"
              f" wrong_pins={s.failed_attempts} expires={_when(s.expires_at)}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    vault = _unlock(_open_db(args.db))
    vault.revoke_share(args.share_id)
    print("Share revoked.")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    conn = _open_db(args.db)
    _unlock(conn)  # the log is only shown to the owner
    for e in store.audit_recent(conn, args.limit):
        print(f"{_when(e.timestamp)}  {e.event:<22} {_printable(e.subject):<24}"
              f" {_printable(e.detail)}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from pwvault.server import create_app

    conn = _open_db(args.db)
    if not is_initialized(conn):
        return _fail("initialise the vault first with `pwvault init`")
    conn.close()
    print(f"Serving {args.db} on http://{args.host}:{args.port} (point your reverse proxy here)")
    uvicorn.run(create_app(args.db), host=args.host, port=args.port,
                proxy_headers=False, server_header=False)
    return 0


def cmd_remote(args: argparse.Namespace) -> int:
    remote = client.RemoteVault(args.url)
    remote.login(getpass.getpass("Master password: "))
    try:
        items = remote.list_entries()
        if args.action == "list":
            for entry_id, meta in items:
                print(f"{entry_id}  {meta.name:<24} {meta.username}")
            return 0
        matches = [i for i, m in items if i == args.query or m.name.lower() == args.query.lower()]
        if len(matches) != 1:
            return _fail(f"no single entry matches {args.query!r}")
        meta, secret = remote.get(matches[0])
        print(f"Name:     {meta.name}\nUsername: {meta.username}\nPassword: {secret.password}")
        return 0
    finally:
        remote.logout()


def cmd_redeem(args: argparse.Namespace) -> int:
    pin: str | Callable[[], str] = args.pin or (lambda: getpass.getpass("PIN: "))
    shared = client.redeem_share(args.url, pin)
    print(f"Account:  {shared.name}\nUsername: {shared.username}\nPassword: {shared.password}")
    return 0


# ---- Parser -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwvault", description=__doc__)
    p.add_argument("--version", action="version", version=f"pwvault {__version__}")
    p.add_argument("--db", type=Path, default=DEFAULT_DB,
                   help=f"vault database (default: {DEFAULT_DB}; or set PWVAULT_DB)")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, func: Callable[[argparse.Namespace], int], help_text: str
            ) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_text)
        sp.set_defaults(func=func)
        return sp

    add("init", cmd_init, "create a new vault")
    add("add", cmd_add, "add an account")
    add("list", cmd_list, "list accounts")
    add("get", cmd_get, "show one account").add_argument("query", help="name or ID")
    add("edit", cmd_edit, "edit an account (a new password ends its shares)").add_argument("query")
    add("rm", cmd_rm, "delete an account (ends its shares)").add_argument("query")
    add("gen", cmd_gen, "generate a password").add_argument("--length", type=int, default=20)
    add("set-url", cmd_set_url, "public URL used in share links").add_argument("url")

    sp = add("share", cmd_share, "share one account with a QR code")
    sp.add_argument("query", help="name or ID of the account to share")
    sp.add_argument("--pin", action="store_true", help="also require a random 6-character PIN")
    sp.add_argument("--ttl", type=parse_duration, default=24 * 3600,
                    help="lifetime, e.g. 30m, 24h, 7d (default 24h)")
    sp.add_argument("--uses", type=int, default=1, help="how many times it can be redeemed")
    sp.add_argument("--base-url", help="override the public URL for this link")
    sp.add_argument("--qr-svg", metavar="FILE", help="also save the QR code as an SVG")

    add("shares", cmd_shares, "list shares and their status")
    add("revoke", cmd_revoke, "revoke a share").add_argument("share_id")
    add("audit", cmd_audit, "show the audit log").add_argument("--limit", type=int, default=50)

    sp = add("serve", cmd_serve, "run the local share server")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=DEFAULT_PORT)

    sp = add("remote", cmd_remote, "use your vault through the server")
    sp.add_argument("url", help="server URL, e.g. https://vault.example.com")
    sp.add_argument("action", choices=["list", "get"])
    sp.add_argument("query", nargs="?", default="")

    sp = add("redeem", cmd_redeem, "open a share link (for recipients)")
    sp.add_argument("url")
    sp.add_argument("--pin", help="PIN, if the share has one (prompted otherwise; prompting"
                    " keeps it out of shell history)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (VaultError, client.ClientError, crypto.CryptoError, ValueError) as exc:
        return _fail(str(exc))
    except httpx.HTTPError as exc:
        return _fail(f"could not reach the server: {exc}")
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

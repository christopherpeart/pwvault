"""Creates a throwaway demo vault for trying the web redeem page locally.

    .venv\\Scripts\\python scripts\\demo_seed.py

Writes demo/demo.db plus demo/demo-links.txt with fresh share links and PINs.
Run it again whenever you want new links: it deletes and recreates the demo vault.
Never put real passwords in it: the master password below is public.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pwvault import store
from pwvault.entries import EntryMeta, EntrySecret
from pwvault.vault import ShareOptions, Vault

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "demo"
DB = DEMO_DIR / "demo.db"
LINKS = DEMO_DIR / "demo-links.txt"
BASE_URL = "http://localhost:8787"
DEMO_MASTER_PASSWORD = "demo-master-password"  # noqa: S105 - public test value


def main() -> None:
    DEMO_DIR.mkdir(exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        Path(f"{DB}{suffix}").unlink(missing_ok=True)

    conn = store.connect(DB)
    vault = Vault.create(conn, DEMO_MASTER_PASSWORD)
    netflix = vault.add(
        EntryMeta("Netflix", "family@example.com", "https://netflix.com"),
        EntrySecret("Popcorn-Night-2026!"),
    )
    wifi = vault.add(EntryMeta("Home Wi-Fi", "", ""), EntrySecret("correct-horse-battery"))
    vault.add(EntryMeta("Bank", "me@example.com", "https://bank.example"),
              EntrySecret("never-shared-9f3K!"))

    shares = [
        ("No PIN, 1 use", vault.create_share(wifi)),
        ("PIN required, 1 use", vault.create_share(netflix, ShareOptions(with_pin=True))),
        ("PIN required, try 3 wrong PINs",
         vault.create_share(netflix, ShareOptions(with_pin=True))),
        ("No PIN, 3 uses", vault.create_share(wifi, ShareOptions(max_uses=3))),
    ]
    conn.close()

    lines = [
        f"pwvault demo links ({datetime.now():%Y-%m-%d %H:%M}), valid 24 hours.",
        f"Server: {BASE_URL}   Demo master password: {DEMO_MASTER_PASSWORD}",
        "",
    ]
    for label, invite in shares:
        lines += [label, f"  {invite.url(BASE_URL)}"]
        if invite.pin:
            lines.append(f"  PIN: {invite.pin}")
        lines.append("")
    LINKS.write_text("\n".join(lines), encoding="utf-8")
    print(f"Demo vault: {DB}\nLinks:      {LINKS}")


if __name__ == "__main__":
    main()

"""The local share server.

Listens on a local address and port; the owner's reverse proxy terminates TLS
and forwards to it. The server does not know the proxy exists: it never trusts
forwarded headers for security decisions, and lockouts count per account and
per share, not per IP. It holds no keys, only ciphertext and hashes.

Owner management (adding, editing, sharing, revoking) happens through the CLI
on the owner's machine, so the API only covers what remote clients need.
"""

# No `from __future__ import annotations` here: FastAPI reads these annotations
# at runtime to build its dependency graph.

import sqlite3
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from pwvault import crypto, store
from pwvault.entries import EncryptedEntry
from pwvault.services import AuthService, LoginStatus, RedeemStatus, ShareService
from pwvault.store import Clock, system_clock

WEB_DIR = Path(__file__).parent / "web"
MAX_BODY_BYTES = 64 * 1024

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';"
        " connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none';"
        " frame-ancestors 'none'"
    ),
}


class LoginBody(BaseModel):
    auth: str = Field(max_length=100)


class RedeemBody(BaseModel):
    token: str = Field(max_length=100)


class BodySizeLimit:
    """Rejects request bodies over MAX_BODY_BYTES, including chunked ones that
    send no Content-Length. Reads the (small) body up front, then replays it."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        too_large = JSONResponse({"detail": "request too large"}, 413)
        length = dict(scope["headers"]).get(b"content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
            await too_large(scope, receive, send)
            return
        body = b""
        while True:
            message = await receive()
            if message["type"] != "http.request":  # client disconnected
                return
            body += message.get("body", b"")
            if len(body) > MAX_BODY_BYTES:
                await too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return await receive()  # waits for disconnect, as Starlette expects
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


def _is_share_id(value: str) -> bool:
    """Share IDs are 16 random bytes in base64url. Anything else is rejected
    before it reaches the database or the audit log."""
    try:
        return len(value) == 22 and len(crypto.b64d(value)) == 16
    except crypto.CryptoError:
        return False


def _decode(value: str, field: str) -> bytes:
    try:
        return crypto.b64d(value)
    except crypto.CryptoError:
        raise HTTPException(400, f"{field} is not valid base64url") from None


def _client(request: Request) -> str:
    """For the audit log only. Forwarded headers are recorded but never trusted."""
    host = request.client.host if request.client else "?"
    forwarded = request.headers.get("x-forwarded-for")
    return f"peer={host}" + (f" fwd(unverified)={forwarded[:100]}" if forwarded else "")


def _entry_json(entry: EncryptedEntry, *, with_secret: bool) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": entry.id,
        "version": entry.version,
        "wrapped_key": crypto.b64e(entry.wrapped_key),
        "meta_ct": crypto.b64e(entry.meta_ct),
    }
    if with_secret:
        data["secret_ct"] = crypto.b64e(entry.secret_ct)
    return data


# ---- Dependencies (module level so FastAPI can resolve the type aliases) -------


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    """One connection per request; SQLite handles locking between them."""
    conn = store.connect(request.app.state.db_path, create_schema=False)
    try:
        yield conn
    finally:
        conn.close()


Db = Annotated[sqlite3.Connection, Depends(get_db)]


def session_token(
    request: Request, conn: Db, authorization: Annotated[str | None, Header()] = None
) -> str:
    token = (authorization or "").removeprefix("Bearer ")
    if not token or not AuthService(conn, request.app.state.clock).validate(token):
        raise HTTPException(401, "login required (or session expired)")
    return token


Session = Annotated[str, Depends(session_token)]


# ---- App factory --------------------------------------------------------------


def create_app(db_path: str | Path, *, clock: Clock = system_clock) -> FastAPI:
    app = FastAPI(title="pwvault", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db_path = str(db_path)
    app.state.clock = clock
    store.connect(db_path).close()  # create the schema before the first request

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    app.add_middleware(BodySizeLimit)

    # ---- Owner: login and encrypted accounts ---------------------------------

    @app.get("/v1/prelogin")
    def prelogin(conn: Db) -> dict[str, Any]:
        settings = store.load_kdf_settings(conn)
        if settings is None:
            raise HTTPException(503, "vault not initialised")
        salt, params = settings
        return {"salt": crypto.b64e(salt), "opslimit": params.opslimit,
                "memlimit": params.memlimit}

    @app.post("/v1/login")
    def login(body: LoginBody, request: Request, conn: Db) -> JSONResponse:
        result = AuthService(conn, clock).login(_decode(body.auth, "auth"), _client(request))
        if result.status is LoginStatus.OK:
            return JSONResponse({"token": result.token})
        if result.status is LoginStatus.LOCKED:
            return JSONResponse(
                {"detail": "login locked", "locked_until": result.locked_until}, status_code=423
            )
        if result.status is LoginStatus.NOT_INITIALIZED:
            raise HTTPException(503, "vault not initialised")
        raise HTTPException(401, "wrong master password")

    @app.post("/v1/logout")
    def logout(token: Session, conn: Db) -> dict[str, bool]:
        AuthService(conn, clock).logout(token)
        return {"ok": True}

    @app.get("/v1/accounts")
    def list_accounts(_: Session, conn: Db) -> dict[str, Any]:
        entries = store.load_all_entries(conn)
        return {"accounts": [_entry_json(e, with_secret=False) for e in entries]}

    @app.get("/v1/accounts/{entry_id}")
    def get_account(entry_id: str, _: Session, conn: Db) -> dict[str, Any]:
        entry = store.load_entry(conn, entry_id)
        if entry is None:
            raise HTTPException(404, "no such account")
        return _entry_json(entry, with_secret=True)

    @app.get("/v1/audit")
    def audit_log(_: Session, conn: Db, limit: int = 50) -> dict[str, Any]:
        events = store.audit_recent(conn, max(1, min(limit, 500)))
        return {"events": [e.__dict__ for e in events]}

    # ---- Public: share redemption -----------------------------------------------

    @app.get("/v1/shares/{share_id}/info")
    def share_info(share_id: str, conn: Db) -> dict[str, bool]:
        if not _is_share_id(share_id):
            return {"has_pin": False, "active": False}
        info = ShareService(conn, clock).info(share_id)
        return {"has_pin": info.has_pin, "active": info.active}

    @app.post("/v1/shares/{share_id}/redeem")
    def redeem(share_id: str, body: RedeemBody, request: Request, conn: Db) -> JSONResponse:
        if not _is_share_id(share_id):
            return JSONResponse({"detail": "this share has ended"}, status_code=410)
        token = _decode(body.token, "token")
        if len(token) != crypto.KEY_SIZE:
            raise HTTPException(400, "token must be 32 bytes")
        result = ShareService(conn, clock).redeem(share_id, token, _client(request))
        if result.status is RedeemStatus.OK and result.blob is not None:
            return JSONResponse({"blob": crypto.b64e(result.blob)})
        if result.status is RedeemStatus.WRONG_TOKEN:
            return JSONResponse(
                {"detail": "wrong PIN", "attempts_left": result.attempts_left}, status_code=403
            )
        if result.status is RedeemStatus.EXPIRED_NOW:
            return JSONResponse(
                {"detail": "wrong PIN; too many attempts, the share has expired"}, status_code=410
            )
        return JSONResponse({"detail": "this share has ended"}, status_code=410)

    @app.get("/s/{share_id}", include_in_schema=False)
    def redeem_page(share_id: str) -> FileResponse:
        return FileResponse(WEB_DIR / "redeem.html", media_type="text/html")

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    return app

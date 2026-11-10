"""FastAPI application: JSON API under /v1, server-rendered pages elsewhere, one app behind two hosts."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, og
from .api import agent, authn, public, reporter, team
from .config import lint_public_copy, strip_template
from .context import get_context
from .db import session
from .mirror import MarkdownMirror
from .ui import render
from .ui import router as ui_router

log = logging.getLogger("desk.app")
HERE = Path(__file__).parent


def template_texts() -> list[str]:
    return [strip_template(p.read_text(encoding="utf-8")) for p in (HERE / "templates").rglob("*.html")]


@asynccontextmanager
async def lifespan(app: FastAPI):
    ctx = get_context()
    logging.basicConfig(
        level=getattr(logging, ctx.settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    await ctx.refresh_node()
    violations = lint_public_copy(ctx.config, template_texts())
    app.state.copy_violations = violations
    if violations:
        log.warning("public copy lint: %d violation(s): %s", len(violations), violations[:5])
    if not ctx.vault.available:
        log.warning("vault key not loaded: private reports cannot be stored or read")
    try:
        async with session() as db:
            await ctx.events.append(
                db,
                "api.started",
                "desk",
                {
                    "version": __version__,
                    "network_id": ctx.node.network_id,
                    "git_commit": ctx.settings.git_commit,
                    "config_hashes": ctx.config.hashes,
                    "copy_lint_violations": len(violations),
                    "hosts": ctx.settings.hosts,
                    "vault": ctx.vault.available,
                },
            )
            await db.commit()
    except Exception as e:
        log.warning("could not write api.started (database not ready?): %s", e)
    yield
    await ctx.aclose()


app = FastAPI(
    title="XE Desk",
    version=__version__,
    lifespan=lifespan,
    docs_url="/v1/docs",
    openapi_url="/v1/openapi.json",
)

app.include_router(public.router)
app.include_router(agent.router)
app.include_router(team.router)
app.include_router(authn.router)
app.include_router(reporter.router)
app.include_router(og.router)
app.include_router(ui_router)
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
app.add_middleware(MarkdownMirror, base_url="")


class BodyLimit:
    """Pure ASGI. A request body is bounded before anything parses it (XE-0777): a JSON body at 1 MB, a
    filing (the one multipart route) at the attachment count times the attachment size plus the report.
    A body that declares more is refused at once; one with no declared length is refused too, since
    every client the desk serves sends one and a chunked upload is the way round the limit."""

    JSON_MAX = 2 << 20

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        limit = self.JSON_MAX
        if scope["path"] == "/v1/reporter/tickets":
            st = get_context().settings
            limit = (st.max_attachments * st.max_attachment_mb << 20) + self.JSON_MAX
        length = headers.get("content-length", "")
        if not length.isdigit():
            if "chunked" in headers.get("transfer-encoding", "").lower():
                return await _refuse(scope, send, 411, "a request body needs a Content-Length")
        elif int(length) > limit:
            return await _refuse(scope, send, 413, "request body too large")
        return await self.app(scope, receive, send)


async def _refuse(scope, send, status: int, why: str):
    if scope["path"].startswith("/v1"):
        resp = JSONResponse({"error": why, "status": status}, status_code=status)
    else:
        resp = PlainTextResponse(why, status_code=status)
    await resp(scope, None, send)


app.add_middleware(BodyLimit)


class NoNul:
    """A NUL in the path or the query string is a 400 here, before any route reads it. Postgres refuses
    one in a parameter, and a lookup that carried it (`/v1/tickets/%00`, `?area=%00`, `/log?kind=%00`)
    ended as a bare 500 (XE-0827 again, at the sites that did not call `clean_lookup`). Checked once,
    for every route there is or will be; JSON bodies are `auth.Body`'s."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and (
            "\x00" in scope.get("path", "") or b"%00" in scope.get("query_string", b"")
        ):
            return await _refuse(scope, send, 400, "the request has a NUL character in it")
        return await self.app(scope, receive, send)


app.add_middleware(NoNul)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError):
    """A 422 that names the fields and says nothing else: the default handler echoes the input, which
    fails to render on non-finite numbers, deep nesting or lone surrogates and becomes a 500 (XE-0826)."""
    problems = []
    for e in exc.errors()[:20]:
        loc = ".".join(str(x) for x in e.get("loc", ()) if x != "body")
        problems.append({"field": loc, "msg": str(e.get("msg", ""))[:200]})
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": "invalid request", "status": 422, "detail": problems}, status_code=422)
    ctx = {"status": 422, "detail": "The request was not valid."}
    return render(request, "error.html", ctx, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/v1"):
        return JSONResponse(
            {"error": exc.detail, "status": exc.status_code},
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )
    return render(
        request, "error.html", {"status": exc.status_code, "detail": exc.detail}, status_code=exc.status_code
    )


@app.exception_handler(Exception)
async def any_error(request: Request, exc: Exception):
    """No bare 500s (the #101 lesson): a JSON or page error with no stack trace."""
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": "internal error", "status": 500}, status_code=500)
    return render(
        request,
        "error.html",
        {"status": 500, "detail": "The desk hit an error. It is logged."},
        status_code=500,
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith("/v1"):
        resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        resp.headers.setdefault("Access-Control-Allow-Headers", "Authorization, Content-Type")
        resp.headers.setdefault("Cache-Control", "no-store")
    elif request.url.path.startswith("/static"):
        # URLs carry a content hash (ui.ASSET_V), so a file may be kept for good; a change is a new URL
        resp.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
    else:
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.options("/v1/{rest:path}", include_in_schema=False)
async def cors_preflight(rest: str):
    return JSONResponse(
        {},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Desk-CSRF",
        },
    )

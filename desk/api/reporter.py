"""The reporter side of /v1: sign in three ways, bind a payout address, file, follow, reply, withdraw.

Sessions are the `desk_reporter` cookie; browser writes carry `X-Desk-CSRF` like the team's, checked
for every cookie write in `deps.current`. Every route that touches a ticket checks ownership here,
since the authorisation matrix only gives a reporter read access to their own private tickets and
nothing else.
"""

from __future__ import annotations

import re
import secrets
import time
from collections import defaultdict
from urllib.parse import quote, urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from starlette.requests import ClientDisconnect

from .. import auth
from ..canonical import DOMAIN_LOGIN, DOMAIN_PAYOUT
from ..models import Challenge, Reporter
from ..services import channels
from ..services import reporters as rsvc
from ..services import tickets as tsvc
from .deps import Body, Ctx, Db, Who, is_multipart

router = APIRouter(prefix="/v1/reporter", tags=["reporter"])

_attempts: dict[str, list[float]] = defaultdict(list)
LIMIT, WINDOW = 12, 600
FILE_LIMIT, FILE_WINDOW = 6, 3600
_filings: dict[str, list[float]] = defaultdict(list)


def _limit(request: Request, table=_attempts, limit=LIMIT, window=WINDOW, what="attempts") -> None:
    ip = auth.client_ip(request) or "?"
    cut = time.time() - window
    hits = [t for t in table[ip] if t > cut]
    if len(hits) >= limit:
        raise HTTPException(429, f"too many {what} from this address; wait a while")
    hits.append(time.time())
    table[ip] = hits


async def _held_reporter(
    db: Db, who: Who, request: Request | None = None
) -> tuple[auth.ReporterSession, Reporter] | None:
    """The reporter session this browser holds, even when it also holds a team session (`who.session`).
    `deps.current` checks the CSRF token of `who.session` (or `who.reporter_session`) on every cookie
    write; a request with neither session holds nothing here."""
    if who.reporter is not None and who.reporter_session is not None:
        return who.reporter_session, who.reporter
    if who.session is not None and request is not None:
        return await auth.reporter_session_from_request(db, request)
    return None


async def _reporter(db: Db, who: Who, request: Request) -> Reporter:
    """The signed-in reporter. The CSRF check on a cookie write is `deps.current`'s, for every route:
    it used to be made here, and the two routes that did not call this (adding a key to a signed-in
    account, and sign-out) went without it (XE-2101, XE-2139)."""
    held = await _held_reporter(db, who, request)
    if held is None:
        raise HTTPException(401, "sign in first")
    return held[1]


def _safe_next(ctx: Ctx, nxt: str | None, default: str = "/my") -> str:
    return auth.safe_next(ctx.settings, nxt, default)


async def _sign_in(ctx: Ctx, db, request: Request, response: Response, r: Reporter, how: str) -> dict:
    s, raw = await auth.create_reporter_session(db, r, how, request)
    await ctx.events.append(
        db, "reporter.login", f"reporter:{r.id}", {"how": how, "ip": auth.client_ip(request)}, public=False
    )
    await db.commit()
    auth.set_session_cookie(response, raw, ctx.settings, name=auth.REPORTER_COOKIE)
    return {"ok": True, "reporter": rsvc.to_dict(r), "csrf": s.csrf}


# ---- GitHub OAuth -----------------------------------------------------------------------------------


def _callback_url(ctx: Ctx) -> str:
    return f"{ctx.settings.scheme}://{ctx.settings.hosts['bounty']}/v1/reporter/auth/github/callback"


class LinkIn(Body):
    next: str | None = None


async def _oauth_state(ctx: Ctx, db: Db, kind: str, nxt: str | None, link_to: int | None) -> str:
    """A provider round trip's state: where to come back to and, when a signed-in reporter is adding
    the identity to their account, which account. `link_to` is written by the two POST routes below
    and by nothing else: adding a way in to an account is a write, a write made with a cookie carries
    the CSRF token (`deps.current`), and a GET carries none. The GET starts used to record it from the
    cookie alone, so a link on another site could start one (the XE-2101 sweep)."""
    state = secrets.token_urlsafe(24)
    detail = {"next": _safe_next(ctx, nxt), "link_to": link_to}
    expires = auth.now() + auth.CHALLENGE_TTL
    db.add(Challenge(id=state, kind=kind, user_id=None, challenge=b"", expires_at=expires, detail=detail))
    await db.commit()
    return state


async def _github_url(ctx: Ctx, db: Db, request: Request, nxt: str | None, link_to: int | None) -> str:
    if not ctx.settings.github_oauth_client_id:
        raise HTTPException(503, "GitHub sign-in is not configured")
    _limit(request)
    q = urlencode(
        {
            "client_id": ctx.settings.github_oauth_client_id,
            "redirect_uri": _callback_url(ctx),
            "scope": "read:user user:email",
            "state": await _oauth_state(ctx, db, "oauth", nxt, link_to),
            "allow_signup": "true",
        }
    )
    return f"https://github.com/login/oauth/authorize?{q}"


@router.get("/auth/github")
async def github_start(ctx: Ctx, db: Db, request: Request, next: str | None = None):
    """Send the browser to GitHub to sign in. Never a link: see `_oauth_state`."""
    return RedirectResponse(await _github_url(ctx, db, request, next, None), status_code=302)


@router.post("/auth/github/link")
async def github_link(ctx: Ctx, db: Db, who: Who, request: Request, body: LinkIn):
    """A signed-in reporter adds GitHub to their account: the address to send the browser to."""
    r = await _reporter(db, who, request)
    return {"url": await _github_url(ctx, db, request, body.next, r.id)}


OAUTH_EXPIRED = "sign-in expired or state mismatch; start again"


async def _take_state(db: Db, state: str, kind: str) -> auth.TakenChallenge:
    """A provider's callback spends its state before anything else, and for good: the take is
    committed here. Left to the request's own commit, a callback that then failed (no code, a code
    the provider refused) rolled the take back, so one state could be presented again and again for
    its five minutes, each time holding the row's lock and a pooled connection across the provider
    round trip (the XE-2053 sweep). Every failure after this already says "start again"."""
    ch = await auth.take_challenge(db, state, kind, OAUTH_EXPIRED)
    await db.commit()
    return ch


async def _link_target(db: Db, ch: auth.TakenChallenge, who: Who, request: Request) -> int | None:
    """The account a sign-in adds its identity to: only the one the asking browser is still signed in as.
    A state handed to another browser (login CSRF) is a plain sign-in there, never a merge."""
    want = ch.detail.get("link_to")
    held = await _held_reporter(db, who, request) if want else None
    if want and held is not None and held[1].id == want:
        return want
    return None


@router.get("/auth/github/callback")
async def github_callback(
    ctx: Ctx, db: Db, who: Who, request: Request, code: str = "", state: str = "", error: str = ""
):
    ch = await _take_state(db, state, "oauth")
    if error or not code:
        raise HTTPException(400, f"GitHub did not sign you in: {error or 'no code'}")
    async with httpx.AsyncClient(timeout=15) as client:
        tok = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": ctx.settings.github_oauth_client_id,
                "client_secret": ctx.settings.github_oauth_client_secret,
                "code": code,
                "redirect_uri": _callback_url(ctx),
            },
        )
        is_json = tok.headers.get("content-type", "").startswith("application/json")
        access = (tok.json() if is_json else {}).get("access_token")
        if not access:
            raise HTTPException(400, "GitHub did not return a token; start again")
        h = {"Authorization": f"Bearer {access}", "Accept": "application/vnd.github+json"}
        user = (await client.get("https://api.github.com/user", headers=h)).json()
        email = ""
        try:
            emails = (await client.get("https://api.github.com/user/emails", headers=h)).json()
            primary = [e for e in emails if e.get("primary") and e.get("verified")]
            email = (primary or [{}])[0].get("email") or ""
        except Exception:
            email = ""
    if not isinstance(user, dict) or "id" not in user:
        raise HTTPException(400, "GitHub returned no user; start again")
    want = await _link_target(db, ch, who, request)
    r = await rsvc.from_github(ctx, db, user, email, link_to=await rsvc.get(db, want) if want else None)
    resp = RedirectResponse(ch.detail.get("next") or "/my", status_code=302)
    await _sign_in(ctx, db, request, resp, r, "github")
    return resp


# ---- Discord OAuth ------------------------------------------------------------------------------------


def _discord_callback_url(ctx: Ctx) -> str:
    return f"{ctx.settings.scheme}://{ctx.settings.hosts['bounty']}/v1/reporter/auth/discord/callback"


async def _discord_url(ctx: Ctx, db: Db, request: Request, nxt: str | None, link_to: int | None) -> str:
    if not ctx.settings.discord_sign_in:
        raise HTTPException(503, "Discord sign-in is not configured")
    _limit(request)
    q = urlencode(
        {
            "client_id": ctx.settings.discord_app_id,
            "redirect_uri": _discord_callback_url(ctx),
            "response_type": "code",
            "scope": "identify email",
            "state": await _oauth_state(ctx, db, "oauth-discord", nxt, link_to),
            "prompt": "none",
        }
    )
    return f"https://discord.com/oauth2/authorize?{q}"


@router.get("/auth/discord")
async def discord_start(ctx: Ctx, db: Db, request: Request, next: str | None = None):
    """Same shape as GitHub. The Discord identity is the one the support bot keys tickets on, so a person
    who asked in Discord and then signs in here finds the thread under /my."""
    return RedirectResponse(await _discord_url(ctx, db, request, next, None), status_code=302)


@router.post("/auth/discord/link")
async def discord_link(ctx: Ctx, db: Db, who: Who, request: Request, body: LinkIn):
    r = await _reporter(db, who, request)
    return {"url": await _discord_url(ctx, db, request, body.next, r.id)}


@router.get("/auth/discord/callback")
async def discord_callback(
    ctx: Ctx, db: Db, who: Who, request: Request, code: str = "", state: str = "", error: str = ""
):
    ch = await _take_state(db, state, "oauth-discord")
    if error or not code:
        raise HTTPException(400, f"Discord did not sign you in: {error or 'no code'}")
    async with httpx.AsyncClient(timeout=15) as client:
        tok = await client.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": ctx.settings.discord_app_id,
                "client_secret": ctx.settings.discord_oauth_client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _discord_callback_url(ctx),
            },
            headers={"Accept": "application/json"},
        )
        access = (tok.json() if tok.status_code == 200 else {}).get("access_token")
        if not access:
            raise HTTPException(400, "Discord did not return a token; start again")
        h = {"Authorization": f"Bearer {access}"}
        user = (await client.get("https://discord.com/api/users/@me", headers=h)).json()
    if not isinstance(user, dict) or "id" not in user:
        raise HTTPException(400, "Discord returned no user; start again")
    want = await _link_target(db, ch, who, request)
    link_to = await rsvc.get(db, want) if want else None
    r = await channels.from_platform(
        ctx,
        db,
        "discord",
        str(user["id"]),
        name=user.get("global_name") or user.get("username") or "",
        handle=user.get("username") or "",
        email=(user.get("email") or "") if user.get("verified") else "",
        link_to=link_to,
    )
    resp = RedirectResponse(ch.detail.get("next") or "/my", status_code=302)
    await _sign_in(ctx, db, request, resp, r, "discord")
    return resp


# ---- email link ---------------------------------------------------------------------------------------


class EmailIn(Body):
    email: str
    next: str | None = None


async def _email_link(
    ctx: Ctx, db, who: Who, email: str, next_path: str, request: Request | None = None
) -> bool:
    """Create a one-time link and mail it. Signed in, the link adds the address to that account and the
    mail says so; otherwise it is a sign-in. Commits. Returns whether mail went out."""
    held = await _held_reporter(db, who, request)
    rep = held[1] if held else None
    existing = await rsvc.by_email(db, email)
    if rep and existing and existing.id != rep.id:
        # never a merge by mail: the person who clicks is not the person who asked
        raise HTTPException(409, "that address is already on another account; sign in there to use it")
    # signed out, the link is a sign-in whether or not the address is known (XE-0363); only a signed-in
    # asker gets a link bound to their account
    link_to = rep.id if rep else None
    raw = await auth.create_reporter_link(db, email, link_to, next_path)
    await db.commit()
    host = ctx.settings.hosts["bounty"]
    url = f"{ctx.settings.scheme}://{host}/v1/reporter/auth/email/{raw}"
    name = ctx.config.copy_public.get("bounty_name", "the XE desk")
    if rep:
        subject = f"Confirm this address for {name}"
        text = (
            "Open this link within fifteen minutes, in the browser where you asked for it, to confirm "
            "the address. The desk will then tell you here when the team replies to your reports:"
            f"\n\n{url}\n\n"
            "If you did not ask for it, ignore it. The link only works in the signed-in browser that "
            "asked, and it never moves an existing account."
        )
    else:
        subject = f"Sign in to {name}"
        text = (
            f"Open this link within fifteen minutes to sign in:\n\n{url}\n\nIf you did not ask for it, ignore it."
        )
    return await auth.send_mail(ctx.settings, email, subject, text)


@router.post("/auth/email")
async def email_start(ctx: Ctx, db: Db, who: Who, request: Request, body: EmailIn):
    """Send a one-time link. Signed out, the response is the same whether or not the address is known."""
    _limit(request)
    sent = await _email_link(ctx, db, who, rsvc.clean_email(body.email), _safe_next(ctx, body.next), request)
    note = None if sent else "mail is not configured on this desk; ask the team"
    return {"ok": True, "sent": sent, "note": note}


@router.get("/auth/email/{token}")
async def email_finish(ctx: Ctx, db: Db, who: Who, request: Request, token: str):
    _limit(request)
    link = await auth.consume_reporter_link(db, token)
    if link is None:
        raise HTTPException(400, "that link has expired or was already used; ask for a new one")
    link_to = None
    if link.reporter_id:
        # a link that adds an address to an account works only in the browser signed in as that account
        held = await _held_reporter(db, who, request)
        if held is None or held[1].id != link.reporter_id:
            raise HTTPException(
                400, "open this link in the browser where you asked for it, signed in to the same account"
            )
        link_to = held[1]
    r = await rsvc.from_email(ctx, db, link.email, link_to=link_to)
    resp = RedirectResponse(link.next_path or "/my", status_code=302)
    await _sign_in(ctx, db, request, resp, r, "email")
    return resp


# ---- XE key -----------------------------------------------------------------------------------------


@router.post("/auth/xe")
async def xe_login(ctx: Ctx, db: Db, who: Who, request: Request, response: Response, req: auth.SignedRequest):
    """A signed request under xe/desk/login/v1. Payload: {"host": <this host>}, and it is checked, so a
    signature made for another deployment is no use here. The address the key derives to is the identity.
    Signed in already: adds the address to that account, which is a cookie write like any other and
    carries the CSRF token (`deps.current`, XE-2101)."""
    _limit(request)
    v = await auth.verify_signed(db, req, DOMAIN_LOGIN)
    if str(v.payload.get("host") or "").lower() not in {h.lower() for h in ctx.settings.hosts.values()}:
        raise HTTPException(401, "the signed host is not this desk; sign in on the page you are on")
    held = await _held_reporter(db, who, request)
    r = await rsvc.from_xe(ctx, db, v, link_to=held[1] if held else None)
    return await _sign_in(ctx, db, request, response, r, "xe")


@router.post("/payout")
async def bind_payout(ctx: Ctx, db: Db, who: Who, request: Request, req: auth.SignedRequest):
    """A signed request under xe/desk/payout/v1 with payload {"address": A}, signed by A's key."""
    r = await _reporter(db, who, request)
    v = await auth.verify_signed(db, req, DOMAIN_PAYOUT)
    out = await rsvc.bind_payout(ctx, db, r, v)
    await db.commit()
    return out


@router.post("/payout/unbind")
async def unbind_payout(ctx: Ctx, db: Db, who: Who, request: Request):
    """Drop the bound payout address. Nothing to sign: the account's session is the authority here, since
    removing an address can only ever stop a payment, not redirect one."""
    r = await _reporter(db, who, request)
    out = await rsvc.unbind_payout(ctx, db, r)
    await db.commit()
    return out


# ---- session ----------------------------------------------------------------------------------------


@router.post("/logout")
async def logout(ctx: Ctx, db: Db, who: Who, request: Request, response: Response):
    """Ends the reporter session this browser holds. Only a request that came with a session ends
    one or clears a cookie: `deps.current` has checked its CSRF token, and a request with none (a form
    on another site, whose POST carries no cookie) changes nothing here (the XE-2101 sweep). A browser
    holding the team's cookie as well is the team member to `who`, and still holds a reporter session
    to end."""
    if await _held_reporter(db, who, request) is not None:
        await auth.end_reporter_session(db, request)
        await db.commit()
        auth.clear_session_cookie(response, ctx.settings, name=auth.REPORTER_COOKIE)
    return {"ok": True}


class UnlinkIn(Body):
    kind: str
    value: str = ""


@router.post("/identities/unlink")
async def unlink_identity(ctx: Ctx, db: Db, who: Who, request: Request, body: UnlinkIn):
    """Take a way in off the account: {"kind": "xe", "value": <address>}, or kind email, github, discord.
    The last way in cannot be removed (XE-0575)."""
    r = await _reporter(db, who, request)
    out = await rsvc.unlink(ctx, db, r, body.kind[:32], body.value)
    await db.commit()
    return out


@router.post("/sessions/revoke-others")
async def revoke_other_sessions(ctx: Ctx, db: Db, who: Who, request: Request):
    """Sign this account out of every other browser and burn its outstanding email links."""
    held = await _held_reporter(db, who, request)
    if held is None:
        raise HTTPException(401, "sign in first")
    rs, r = held
    n = await rsvc.end_other_sessions(db, r, keep=rs.id)
    await ctx.events.append(db, "reporter.sessions_ended", f"reporter:{r.id}", {"n": n}, public=False)
    await db.commit()
    return {"ended": n}


@router.get("/me")
async def me(ctx: Ctx, db: Db, who: Who, request: Request):
    held = await _held_reporter(db, who, request)
    if held is None:
        return {"reporter": None}
    _, rep = held
    mine = await rsvc.my_tickets(db, rep)
    hidden = await tsvc.hidden_targets(db, who.principal, mine)
    return {
        "reporter": rsvc.to_dict(rep),
        "csrf": who.csrf,
        "tickets": [tsvc.to_dict(ctx, t, who.principal, hidden=hidden) for t in mine],
        "github_sign_in": bool(ctx.settings.github_oauth_client_id),
        "discord_sign_in": ctx.settings.discord_sign_in,
        "mail": bool(ctx.settings.smtp_host),
    }


# ---- filing -----------------------------------------------------------------------------------------


_TEXT = {"type": "string"}
FILING_FORM = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["title", "body"],
                    "properties": {
                        "title": _TEXT,
                        "body": _TEXT,
                        "kind": {"type": "string", "default": "bounty"},
                        "area": _TEXT,
                        "claimed_tier": _TEXT,
                        "private": {"type": "boolean", "default": False},
                        "notify_email": _TEXT,
                        "files": {"type": "array", "items": {"type": "string", "format": "binary"}},
                    },
                }
            }
        },
    }
}
_YES, _NO = frozenset({"true", "1", "on", "yes"}), frozenset({"false", "0", "off", "no"})


def _form_text(form, name: str, *, required: bool = False) -> str | None:
    """One text field of the filing form. An empty value is no value, as it was when FastAPI read it."""
    v = form.get(name)
    if v is not None and not isinstance(v, str):
        raise HTTPException(422, f"{name} is text, not a file")
    if not v:
        if required:
            raise HTTPException(422, f"{name} is required")
        return None
    return v


@router.post("/tickets", openapi_extra=FILING_FORM)
async def file_ticket(ctx: Ctx, db: Db, who: Who, request: Request):
    """Multipart, so attachments ride along. Returns the ticket id and URL; the page redirects there.
    `notify_email`, on an account with no email yet, gets a confirmation link; once confirmed, replies
    are announced there.

    The form is read here, once the caller is known and counted, and not through `Form` parameters:
    FastAPI reads a declared body before it resolves who is calling, so the filing's allowance (its
    attachments' worth, where every other route has 2 MB) was read and parsed for anyone who sent
    one (XE-1905). The route declares no body, so nothing is read for a caller who is refused."""
    r = await _reporter(db, who, request)
    _limit(request, _filings, FILE_LIMIT, FILE_WINDOW, "reports")
    if not is_multipart(request.headers.get("content-type")):
        raise HTTPException(415, "a report is filed as multipart/form-data")
    try:
        form = await request.form()
    except ClientDisconnect:
        raise HTTPException(400, "the upload was cut off") from None
    try:
        private = (_form_text(form, "private") or "false").strip().lower()
        if private not in _YES | _NO:
            raise HTTPException(422, "private is true or false")
        f = rsvc.Filing(
            kind=_form_text(form, "kind") or "bounty",
            title=_form_text(form, "title", required=True),
            body=_form_text(form, "body", required=True),
            area=_form_text(form, "area"),
            claimed_tier=_form_text(form, "claimed_tier"),
            private=private in _YES,
            files=[u for u in form.getlist("files") if not isinstance(u, str) and u.filename],
        )
        notify_email = _form_text(form, "notify_email")
        t = await rsvc.file_ticket(ctx, db, r, f)
        await db.commit()
    finally:
        await form.close()
    url = tsvc.ticket_url(ctx, t)
    notify = None
    if notify_email and notify_email.strip() and not r.email:
        try:
            notify = await _email_link(
                ctx, db, who, rsvc.clean_email(notify_email), _safe_next(ctx, url), request
            )
        except HTTPException:
            notify = False  # a bad address never costs the filing
    return {"ticket": t.id, "url": url, "visibility": t.visibility, "notify_sent": notify, "queued": t.queued}


class TextIn(Body):
    body: str = ""


@router.post("/tickets/{tid}/messages")
async def reporter_reply(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: TextIn):
    r = await _reporter(db, who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    m = await rsvc.reply(ctx, db, r, t, body.body)
    await db.commit()
    return {"ok": True, "message": m.id if m else None, "status": t.status}


@router.post("/tickets/{tid}/withdraw")
async def reporter_withdraw(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: TextIn):
    r = await _reporter(db, who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    await rsvc.withdraw(ctx, db, r, t, body.body)
    await db.commit()
    return {"ok": True, "status": t.status, "closed_reason": t.closed_reason}


@router.get("/tickets/{tid}/attachments")
async def list_attachments(ctx: Ctx, db: Db, who: Who, request: Request, tid: str):
    t = await tsvc.get_for(db, who.principal, tid)
    held = await _held_reporter(db, who, request)
    if not (who.principal.is_team or rsvc.owns(held[1] if held else None, t)):
        raise HTTPException(403, "attachments open for the reporter and the team only")
    rows = await rsvc.attachments_for(db, t)
    return {
        "attachments": [
            {"n": a.n, "filename": a.filename, "size": a.size, "sha256": a.sha256, "sealed": a.sealed}
            for a in rows
        ]
    }


@router.get("/tickets/{tid}/attachments/{n}")
async def get_attachment(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, n: int):
    t = await tsvc.get_for(db, who.principal, tid)
    held = await _held_reporter(db, who, request)
    if not (who.principal.is_team or rsvc.owns(held[1] if held else None, t)):
        raise HTTPException(403, "attachments open for the reporter and the team only")
    a, data = await rsvc.open_attachment(ctx, db, who.principal, t, n)
    await db.commit()
    # headers are latin-1; the real name travels RFC 5987-encoded beside an ASCII fallback
    ascii_name = re.sub(r'[^A-Za-z0-9._-]', "_", a.filename.encode("ascii", "replace").decode()) or "file"
    disposition = f'attachment; filename="{ascii_name}"'
    if ascii_name != a.filename:
        disposition += f"; filename*=UTF-8''{quote(a.filename, safe='')}"
    return Response(
        content=data,
        media_type="application/octet-stream",  # never rendered inline, whatever it claims to be
        headers={
            "Content-Disposition": disposition,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "X-Desk-SHA256": a.sha256,
        },
    )


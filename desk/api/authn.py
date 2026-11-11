"""Team sign-in: passkeys first, a TOTP code as the fallback, a one-time invite link for the first
visit. No passwords. Sign-in attempts are rate limited per address in memory; a stricter limit belongs
in Caddy."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import delete, select

from .. import auth
from ..models import Passkey
from ..services import users
from .deps import Body, Ctx, Db, Who

router = APIRouter(prefix="/v1/auth", tags=["auth"])

_attempts: dict[str, list[float]] = defaultdict(list)
LIMIT, WINDOW = 10, 600


def _limit(request: Request) -> None:
    ip = auth.client_ip(request) or "?"
    cut = time.time() - WINDOW
    hits = [t for t in _attempts[ip] if t > cut]
    if len(hits) >= LIMIT:
        raise HTTPException(429, "too many sign-in attempts; wait ten minutes")
    hits.append(time.time())
    _attempts[ip] = hits


async def _sign_in(ctx: Ctx, db, request: Request, response: Response, user, how: str) -> dict:
    s, raw = await auth.create_session(db, user, request)
    await ctx.events.append(
        db, "team.login", f"user:{user.id}", {"how": how, "ip": auth.client_ip(request)}, public=False
    )
    await db.commit()
    auth.set_session_cookie(response, raw, ctx.settings)
    return {"ok": True, "user": users.user_dict(user), "csrf": s.csrf}


# ---- passkeys ---------------------------------------------------------------------------------------


class BeginLoginIn(Body):
    email: str | None = None


class FinishIn(Body):
    challenge_id: str
    credential: Any
    label: str = ""


@router.post("/passkey/login/begin")
async def passkey_login_begin(ctx: Ctx, db: Db, request: Request, body: BeginLoginIn):
    _limit(request)
    out = await auth.passkey_begin_login(db, ctx.settings, body.email)
    await db.commit()
    return out


@router.post("/passkey/login/finish")
async def passkey_login_finish(ctx: Ctx, db: Db, request: Request, response: Response, body: FinishIn):
    _limit(request)
    user = await auth.passkey_finish_login(db, ctx.settings, body.challenge_id, body.credential)
    return await _sign_in(ctx, db, request, response, user, "passkey")


@router.post("/passkey/register/begin")
async def passkey_register_begin(ctx: Ctx, db: Db, who: Who, request: Request):
    _session(who, request)
    out = await auth.passkey_begin_registration(db, ctx.settings, who.principal.user)
    await db.commit()
    return out


@router.post("/passkey/register/finish", status_code=201)
async def passkey_register_finish(ctx: Ctx, db: Db, who: Who, request: Request, body: FinishIn):
    _session(who, request)
    pk = await auth.passkey_finish_registration(
        db, ctx.settings, who.principal.user, body.challenge_id, body.credential, body.label
    )
    await ctx.events.append(
        db, "team.passkey_added", who.principal.actor, {"passkey": pk.id, "label": pk.label}, public=False
    )
    await db.commit()
    return {"id": pk.id, "label": pk.label}


@router.delete("/passkeys/{pid}")
async def passkey_remove(ctx: Ctx, db: Db, who: Who, request: Request, pid: int):
    _session(who, request)
    u = who.principal.user
    pk = (
        await db.execute(select(Passkey).where(Passkey.id == pid, Passkey.user_id == u.id))
    ).scalar_one_or_none()
    if pk is None:
        raise HTTPException(404, "no such passkey")
    others = len(await users.passkeys_for(db, u)) - 1
    if others == 0 and not u.totp_secret:
        raise HTTPException(400, "that is your only way in; add another passkey or set up a code first")
    await db.execute(delete(Passkey).where(Passkey.id == pid))
    await ctx.events.append(db, "team.passkey_removed", who.principal.actor, {"passkey": pid}, public=False)
    await db.commit()
    return {"removed": pid}


# ---- TOTP -------------------------------------------------------------------------------------------


class TotpLoginIn(Body):
    email: str
    code: str


class TotpConfirmIn(Body):
    challenge_id: str
    code: str


@router.post("/totp/login")
async def totp_login(ctx: Ctx, db: Db, request: Request, response: Response, body: TotpLoginIn):
    _limit(request)
    u = await users.by_email(db, body.email)
    # one answer whether the address is a member, is active, or has a code set up (XE-0523)
    step = None
    if u is not None and u.active and u.roles and u.totp_secret:
        try:
            secret = ctx.vault.open_text(u.totp_secret)
        except Exception:
            raise HTTPException(503, "the vault key is not loaded; codes cannot be checked") from None
        step = auth.totp_verify(secret, body.code, after_step=u.totp_last_step or 0)
        # a code is accepted once (XE-0820): the step is claimed in one statement, so a second request
        # with the same code, however close behind, is the one that fails (XE-1735)
        if step is not None and not await auth.claim_totp_step(db, u, step):
            step = None
    if step is None:
        if u is not None:
            await ctx.events.append(
                db,
                "team.login_failed",
                f"user:{u.id}",
                {"how": "totp", "ip": auth.client_ip(request)},
                public=False,
            )
            await db.commit()
        raise HTTPException(401, "that address and code do not match")
    return await _sign_in(ctx, db, request, response, u, "totp")


@router.post("/totp/setup")
async def totp_setup(ctx: Ctx, db: Db, who: Who, request: Request):
    """A fresh secret, held server-side as a challenge until the first code confirms the app has it."""
    _session(who, request)
    if not ctx.vault.available:
        raise HTTPException(503, "the vault key is not loaded")
    secret = auth.totp_new_secret()
    cid = await auth._store_challenge(db, "totp", secret.encode("ascii"), who.principal.user.id)
    await db.commit()
    return {
        "challenge_id": cid,
        "secret": secret,
        "uri": auth.totp_uri(secret, who.principal.user.email, ctx.settings.webauthn_rp_name),
    }


@router.post("/totp/confirm")
async def totp_confirm(ctx: Ctx, db: Db, who: Who, request: Request, body: TotpConfirmIn):
    _session(who, request)
    ch = await auth.take_challenge(db, body.challenge_id, "totp")
    u = who.principal.user
    if ch.user_id != u.id:
        raise HTTPException(400, "that setup belongs to another sign-in")
    secret = ch.challenge.decode("ascii")
    step = auth.totp_verify(secret, body.code)
    if step is None:
        raise HTTPException(400, "the code did not match; try the next one")
    u.totp_secret = ctx.vault.seal_text(secret)
    u.totp_last_step = step
    await ctx.events.append(db, "team.totp_set", who.principal.actor, {}, public=False)
    await db.commit()
    return {"ok": True}


@router.delete("/totp")
async def totp_remove(ctx: Ctx, db: Db, who: Who, request: Request):
    _session(who, request)
    u = who.principal.user
    if not await users.passkeys_for(db, u):
        raise HTTPException(400, "add a passkey before removing the code")
    u.totp_secret = None
    await ctx.events.append(db, "team.totp_removed", who.principal.actor, {}, public=False)
    await db.commit()
    return {"ok": True}


# ---- invites and sessions ---------------------------------------------------------------------------


class InviteIn(Body):
    token: str


@router.post("/invite/accept")
async def invite_accept(ctx: Ctx, db: Db, request: Request, response: Response, body: InviteIn):
    _limit(request)
    u = await auth.consume_invite(db, body.token)
    if u is None:
        raise HTTPException(400, "that link has been used or has expired; ask for another")
    return await _sign_in(ctx, db, request, response, u, "invite")


@router.post("/invite/{uid}")
async def invite_create(ctx: Ctx, db: Db, who: Who, request: Request, uid: int):
    """An admin mints an invite link for a user; the link is returned and, when SMTP is set, emailed."""
    _session(who, request)
    if "admin" not in who.principal.roles:
        raise HTTPException(403, "admins send invites")
    u = await users.by_id(db, uid)
    if u is None:
        raise HTTPException(404, "no such user")
    raw = await auth.create_invite(db, u, "invite")
    url = f"{ctx.settings.scheme}://{ctx.settings.hosts['bounty']}/team/invite/{raw}"
    await ctx.events.append(db, "team.invited", who.principal.actor, {"user": u.id}, public=False)
    await db.commit()
    sent = await auth.send_mail(
        ctx.settings,
        u.email,
        "Your XE desk invite",
        f"Open this link within seven days to set up your passkey:\n\n{url}\n",
    )
    return {"url": url, "emailed": sent}


@router.post("/logout")
async def logout(ctx: Ctx, db: Db, who: Who, request: Request, response: Response):
    """Ends the team session this browser holds. A request that came with no session clears no
    cookie: it carried no CSRF token to check (the XE-2101 sweep)."""
    if who.session is not None:
        await auth.end_session(db, request)
        await db.commit()
        auth.clear_session_cookie(response, ctx.settings)
    return {"ok": True}


@router.get("/session")
async def session_info(db: Db, who: Who):
    p = who.principal
    if p.kind != "user":
        return {"signed_in": False}
    return {
        "signed_in": True,
        "user": users.user_dict(p.user),
        "csrf": who.session.csrf if who.session else "",
        "passkeys": [
            {
                "id": k.id,
                "label": k.label,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            }
            for k in await users.passkeys_for(db, p.user)
        ],
        "totp": bool(p.user.totp_secret),
    }


def _session(who: Who, request: Request) -> None:
    """A team member in a browser session. The CSRF check on the write is `deps.current`'s."""
    if who.principal.kind != "user" or who.session is None:
        raise HTTPException(401, "sign in first")

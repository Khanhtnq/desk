"""Team-only JSON, called from the pages' small scripts with the session cookie and the CSRF header.
Every route refuses tokens through the authorisation layer. Mutations commit here."""

from __future__ import annotations

import csv
import io
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from ..auth import check_csrf
from ..authz import can, require, require_field
from ..services import proposals as psvc
from ..services import reporters as rsvc
from ..services import notify, thread, users
from ..services import tickets as tsvc
from .deps import Ctx, Db, Who

router = APIRouter(prefix="/v1/team", tags=["team"])


def _team(who: Who, request: Request) -> None:
    p = who.principal
    if p.kind != "user" or not p.roles:
        raise HTTPException(401 if p.kind == "anon" else 403, "team sign-in required")
    if who.session is not None and request.method not in ("GET", "HEAD"):
        check_csrf(request, who.session)


class FactsIn(BaseModel):
    changes: dict[str, Any]
    reason: str = Field(default="", max_length=500)


class ReporterIn(BaseModel):
    reporter_id: int | None = None
    email: str | None = Field(default=None, max_length=256)


class StatusIn(BaseModel):
    status: str
    closed_reason: str | None = None
    reason: str = Field(default="", max_length=500)


class ReplyIn(BaseModel):
    body: str = Field(min_length=1, max_length=20_000)


class DecideIn(BaseModel):
    reason: str = Field(default="", max_length=500)


class AwardIn(BaseModel):
    award_xe: int | None = None
    approve: bool | None = None  # True approves, False takes approval back, None leaves it


class NewTicketIn(BaseModel):
    kind: str = Field(default="bounty", max_length=16)
    title: str = Field(min_length=3, max_length=512)
    body: str = Field(default="", max_length=60_000)
    visibility: str = Field(default="public", max_length=16)
    source: str = Field(default="web", max_length=16)
    area: str | None = Field(default=None, max_length=32)
    claimed_tier: str | None = Field(default=None, max_length=16)


# ---- tickets ----------------------------------------------------------------------------------------


@router.post("/tickets", status_code=201)
async def create_ticket(ctx: Ctx, db: Db, who: Who, request: Request, body: NewTicketIn):
    _team(who, request)
    spec = tsvc.NewTicket(
        kind=body.kind,
        title=body.title,
        body=body.body,
        visibility=body.visibility,
        source=body.source,
        area=body.area,
        claimed_tier=body.claimed_tier,
    )
    t = await tsvc.create(ctx, db, who.principal.actor, spec)
    await db.commit()
    return tsvc.to_dict(ctx, t, who.principal)


@router.patch("/tickets/{tid}/facts")
async def set_facts(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: FactsIn):
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    for k in body.changes:
        require_field(who.principal, k)
    diff = await tsvc.set_facts(ctx, db, who.principal, t, body.changes, reason=body.reason)
    await db.commit()
    return {"ticket": t.id, "changes": diff}


@router.post("/tickets/{tid}/status")
async def set_status(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: StatusIn):
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    require_field(who.principal, "status")
    if body.status == "disclosed":
        await tsvc.disclose(ctx, db, who.principal, t)
    else:
        await tsvc.set_status(
            ctx, db, who.principal, t, body.status, closed_reason=body.closed_reason, reason=body.reason
        )
    await db.commit()
    return tsvc.to_dict(ctx, t, who.principal)


@router.post("/tickets/{tid}/kind")
async def set_kind(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, kind: str):
    """Support that turns out to be a bug (or the reverse). The id and the history stay."""
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "facts", t)
    if kind not in ("bounty", "support") or kind == t.kind:
        raise HTTPException(400, "kind is bounty or support, and must change")
    settled = ("accepted", "fixing", "patched", "disclosed", "awarded", "paid")
    if t.award_xe or t.award_approved_at or t.status in settled:
        # a report that has been accepted, or carries an award, is a bounty record; it is closed or
        # paid as one, never walked back through a conversion (XE-0789)
        raise HTTPException(409, f"a {t.status} ticket with a bounty record is not converted; close it")
    old = t.kind
    t.kind = kind
    t.area = None  # areas are engineering areas on the bounty and topics on support; neither carries over
    if kind == "support" and t.status not in ("new", "triaging", "needs-info", "closed"):
        await tsvc.set_status(ctx, db, who.principal, t, "triaging", reason="converted to support")
    await ctx.events.append(
        db,
        "ticket.kind",
        who.principal.actor,
        {"ticket": t.id, "from": old, "to": kind},
        ref=t.id,
        public=t.visibility == "public",
    )
    await db.commit()
    return tsvc.to_dict(ctx, t, who.principal)


@router.post("/tickets/{tid}/replies", status_code=201)
async def reply(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: ReplyIn):
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "reply", t)
    r = await thread.add_reply(ctx, db, who.principal, t, body.body)
    await db.commit()
    # once it is on record, the reporter is told, where there is an address to tell
    told = await notify.reply_to_reporter(ctx, db, t, who.principal.name, body.body)
    return {"id": r.id, "ticket": t.id, "mirror": r.mirror, "mailed": told}


@router.get("/tickets/{tid}/reply-template/{name}")
async def reply_template(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, name: str):
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    if name not in ctx.config.reply_templates:
        raise HTTPException(404, "no such template")
    prs = await thread.patches_for(db, t)
    refs = (
        ", ".join(f"{p.repo}#{p.ref}" if p.kind == "pr" else f"{p.repo}@{p.ref[:10]}" for p in prs)
        or "the linked PR"
    )
    return {"name": name, "body": thread.render_template(ctx, name, t, patch_refs=refs)}


@router.post("/tickets/{tid}/reporter")
async def set_reporter(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: ReporterIn):
    """Attach the reporter to a ticket that arrived without one. Existing reporter by id, or by email."""
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "facts", t)
    r = await rsvc.attach(ctx, db, who.principal, t, reporter_id=body.reporter_id, email=body.email)
    await db.commit()
    return {"ticket": t.id, "reporter_id": r.id, "reporter": rsvc.label(r)}


@router.post("/tickets/{tid}/award")
async def award(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: AwardIn):
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "award", t)
    await tsvc.set_award(ctx, db, who.principal, t, body.award_xe, approve=body.approve)
    await db.commit()
    return tsvc.to_dict(ctx, t, who.principal)


class PaidIn(BaseModel):
    paid_ref: str = Field(min_length=1, max_length=64)


@router.post("/tickets/{tid}/paid")
async def paid(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: PaidIn):
    """The treasurer records the payment reference; the ticket goes from awarded to paid (XE-0737)."""
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "award", t)
    await tsvc.mark_paid(ctx, db, who.principal, t, body.paid_ref)
    await db.commit()
    return tsvc.to_dict(ctx, t, who.principal)


# ---- proposals --------------------------------------------------------------------------------------


@router.post("/proposals/{pid}/adopt")
async def adopt(ctx: Ctx, db: Db, who: Who, request: Request, pid: int, body: DecideIn | None = None):
    _team(who, request)
    pr = await psvc.get(db, pid)
    if pr is None:
        raise HTTPException(404, "no such proposal")
    out = await psvc.decide(ctx, db, who.principal, pr, True, reason=(body.reason if body else ""))
    await db.commit()
    text = out.pop("reply_text", None)
    if out.get("sent") and text:  # a close-as-duplicate told the reporter; the mail follows the commit
        t = await tsvc.get(db, out["ticket"])
        if t is not None:
            out["mailed"] = await notify.reply_to_reporter(ctx, db, t, who.principal.name, text)
    return out


@router.post("/proposals/{pid}/reject")
async def reject(ctx: Ctx, db: Db, who: Who, request: Request, pid: int, body: DecideIn | None = None):
    _team(who, request)
    pr = await psvc.get(db, pid)
    if pr is None:
        raise HTTPException(404, "no such proposal")
    out = await psvc.decide(ctx, db, who.principal, pr, False, reason=(body.reason if body else ""))
    await db.commit()
    return out


class BulkIn(BaseModel):
    adopt: list[int] = []
    reject: list[int] = []
    send_plain: bool = False  # send reply drafts the desk reads as plain acknowledgements (the triage page)


class FamilyIn(BaseModel):
    tickets: list[str] | None = None  # a subset of the family; all of it when omitted


@router.get("/tickets/{tid}/duplicates")
async def pending_duplicates(ctx: Ctx, db: Db, who: Who, request: Request, tid: str):
    """The family: open tickets an agent has proposed as duplicates of this one, still waiting."""
    _team(who, request)
    t = await tsvc.get_for(db, who.principal, tid)
    rows = await psvc.pending_duplicates_of(db, t.id)
    return {
        "canonical": t.id,
        "tickets": [
            {**tsvc.to_dict(ctx, o, who.principal), "proposal": psvc.to_dict(pr) if pr else None}
            for o, pr in rows
        ],
    }


@router.post("/tickets/{tid}/duplicates/close")
async def close_duplicates(
    ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: FamilyIn | None = None
):
    """One ruling for the family: each pending duplicate of `tid` is marked, closed and told, under the
    person clicking. Tickets the desk refuses are reported in `skipped`, untouched."""
    _team(who, request)
    canon = await tsvc.get_for(db, who.principal, tid)
    out = await psvc.close_duplicates(ctx, db, who.principal, canon, only=body.tickets if body else None)
    await db.commit()
    for d in out["closed"]:
        t = await tsvc.get(db, d["ticket"])
        text = d.pop("text")
        if t is not None:
            d["mailed"] = await notify.reply_to_reporter(ctx, db, t, who.principal.name, text)
    return out


@router.post("/proposals/bulk")
async def decide_bulk(ctx: Ctx, db: Db, who: Who, request: Request, body: BulkIn):
    """Adopt and reject in one request. Each decision is its own savepoint: one the desk refuses is
    listed under `skipped` with the reason and the rest go through. With `send_plain`, a reply draft the
    desk reads as a plain acknowledgement goes to the reporter under your name; the rest wait as drafts
    with `review` saying why."""
    _team(who, request)
    out = await psvc.decide_many(ctx, db, who.principal, body.adopt, body.reject, send_plain=body.send_plain)
    await db.commit()
    for d in out["decided"]:
        text = d.pop("reply_text", None)
        if d.get("sent") and text:
            t = await tsvc.get(db, d["ticket"])
            if t is not None:
                d["mailed"] = await notify.reply_to_reporter(ctx, db, t, who.principal.name, text)
    return out


# ---- views ------------------------------------------------------------------------------------------


@router.get("/outbox")
async def outbox(ctx: Ctx, db: Db, who: Who, request: Request, kind: str = "bounty"):
    _team(who, request)
    if kind not in ("bounty", "support"):
        raise HTTPException(400, "kind is bounty or support")
    rows = await tsvc.outbox(db, ctx.config, who.principal, kind=kind)
    return {"tickets": [tsvc.to_dict(ctx, t, who.principal) for t in rows]}


@router.get("/release")
async def release(ctx: Ctx, db: Db, who: Who, request: Request):
    _team(who, request)
    groups = await tsvc.release_view(db, ctx.config, who.principal)
    return {area: [tsvc.to_dict(ctx, t, who.principal) for t in ts] for area, ts in groups.items()}


@router.get("/payouts")
async def payouts(ctx: Ctx, db: Db, who: Who, request: Request):
    """Approved awards not yet paid, with addresses: the treasurer's list."""
    _team(who, request)
    require(who.principal, "export:payouts")
    rows = await rsvc.payout_rows(db)  # the same rows as payouts.csv (XE-0711)
    return {
        "payouts": [
            {
                "ticket": r["ticket"],
                "award_xe": r["award_xe"],
                "payout_address": r["xe_address"],
                "stamped_address": r["stamped_address"],
                "address_changed": r["address_changed"],
                "reporter_id": r["reporter_id"],
                "tier": r["tier"] or None,
            }
            for r in rows
        ]
    }


# ---- tokens and users -------------------------------------------------------------------------------


class TokenIn(BaseModel):
    model_id: str = Field(min_length=1, max_length=128)
    label: str = Field(default="", max_length=128)
    scopes: list[str]
    days: int = 90
    owner_id: int | None = None
    instructions: str = Field(default="", max_length=4000)


class InstructionsIn(BaseModel):
    instructions: str = Field(default="", max_length=4000)


@router.get("/tokens")
async def list_tokens(db: Db, who: Who, request: Request):
    _team(who, request)
    mine = None if can(who.principal, "admin") else who.principal.user
    return {"tokens": [users.token_dict(t) for t in await users.tokens_for(db, mine)]}


@router.post("/tokens", status_code=201)
async def issue_token(ctx: Ctx, db: Db, who: Who, request: Request, body: TokenIn):
    _team(who, request)
    require(who.principal, "tokens:issue")
    owner = who.principal.user
    if body.owner_id and body.owner_id != owner.id:
        owner = await users.by_id(db, body.owner_id)
        if owner is None:
            raise HTTPException(404, "no such user")
    t, raw = await users.issue(
        ctx, db, who.principal, owner, body.model_id, body.label, body.scopes, body.days, body.instructions
    )
    await db.commit()
    return {**users.token_dict(t), "token": raw, "note": "shown once; store it now"}


@router.patch("/tokens/{tid}")
async def instruct_token(ctx: Ctx, db: Db, who: Who, request: Request, tid: int, body: InstructionsIn):
    _team(who, request)
    t = await users.token_by_id(db, tid)
    if t is None:
        raise HTTPException(404, "no such token")
    await users.set_instructions(ctx, db, who.principal, t, body.instructions)
    await db.commit()
    return users.token_dict(t)


@router.delete("/tokens/{tid}")
async def revoke_token(ctx: Ctx, db: Db, who: Who, request: Request, tid: int):
    _team(who, request)
    t = await users.token_by_id(db, tid)
    if t is None:
        raise HTTPException(404, "no such token")
    await users.revoke(ctx, db, who.principal, t)
    await db.commit()
    return {"revoked": t.id}


class UserIn(BaseModel):
    email: str = Field(max_length=256)
    name: str = Field(default="", max_length=128)
    roles: list[str] = []


@router.get("/users")
async def list_users(db: Db, who: Who, request: Request):
    _team(who, request)
    return {"users": [users.user_dict(u) for u in await users.list_users(db)]}


@router.post("/users", status_code=201)
async def add_user(ctx: Ctx, db: Db, who: Who, request: Request, body: UserIn):
    _team(who, request)
    require(who.principal, "admin")
    u = await users.create_user(ctx, db, who.principal.actor, body.email, body.name, body.roles)
    await db.commit()
    return users.user_dict(u)


class UserEditIn(BaseModel):
    roles: list[str] | None = None
    active: bool | None = None
    name: str | None = None
    email: str | None = None


class NameIn(BaseModel):
    name: str


class EmailIn(BaseModel):
    email: str


@router.post("/account/email")
async def change_my_email(ctx: Ctx, db: Db, who: Who, request: Request, body: EmailIn):
    """Your own sign-in email. Passkeys and the code stay; only the address you type at sign-in changes."""
    _team(who, request)
    await users.set_email(ctx, db, who.principal.actor, who.principal.user, body.email)
    await db.commit()
    return users.user_dict(who.principal.user)


@router.post("/account/name")
async def rename_me(ctx: Ctx, db: Db, who: Who, request: Request, body: NameIn):
    """Your own display name, the one on your replies."""
    _team(who, request)
    await users.set_name(ctx, db, who.principal.actor, who.principal.user, body.name)
    await db.commit()
    return users.user_dict(who.principal.user)


@router.patch("/users/{uid}")
async def edit_user(ctx: Ctx, db: Db, who: Who, request: Request, uid: int, body: UserEditIn):
    _team(who, request)
    require(who.principal, "admin")
    u = await users.by_id(db, uid)
    if u is None:
        raise HTTPException(404, "no such user")
    if body.name is not None:
        await users.set_name(ctx, db, who.principal.actor, u, body.name)
    if body.email is not None:
        await users.set_email(ctx, db, who.principal.actor, u, body.email)
    if body.roles is not None:
        await users.set_roles(ctx, db, who.principal.actor, u, body.roles)
    if body.active is not None:
        await users.set_active(ctx, db, who.principal.actor, u, body.active)
    await db.commit()
    return users.user_dict(u)


@router.get("/payouts.csv")
async def payouts_csv(ctx: Ctx, db: Db, who: Who, request: Request):
    """Tickets at `awarded` with an approved amount, one row each, for the mainnet-launch payout. Those
    with no bound address are listed too, address blank, so nobody is missed; paid and closed never are."""
    _team(who, request)
    require(who.principal, "export:payouts")
    rows = await rsvc.payout_rows(db)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(rsvc.PAYOUT_COLUMNS)
    for r in rows:
        cells = dict(r, award_xe=r["award_xe"] // 1_000_000, reporter_id=r["reporter_id"] or "")
        w.writerow([rsvc.csv_cell(cells[c]) for c in rsvc.PAYOUT_COLUMNS])
    return Response(
        content=out.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="payouts.csv"', "Cache-Control": "no-store"},
    )

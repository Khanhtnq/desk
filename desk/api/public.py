"""Public JSON: the manifest, tickets as the caller may see them, the log, the stream, health, the
triage export, and the GitHub webhook. Everything here is readable anonymously except what the
authorisation layer narrows per ticket."""

from __future__ import annotations

import asyncio
import json
import time

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sse_starlette.sse import EventSourceResponse

from .. import __version__
from ..authz import can, can_see
from ..db import session
from ..log import REPORTER_KINDS, EventLog, event_to_dict
from ..models import HealthCheck, SeenDelivery
from ..services import github as gh
from ..services import proposals as psvc
from ..services import sync, thread, triage
from ..services import tickets as tsvc
from .deps import Ctx, Db, Who

router = APIRouter(prefix="/v1", tags=["public"])


@router.get("")
async def manifest(ctx: Ctx, db: Db):
    head = await EventLog.head(db)
    s = ctx.settings
    return {
        "name": "xe-desk",
        "version": __version__,
        "git_commit": s.git_commit,
        "network": {"id": ctx.node.network_id, "node": s.xe_node_url, "badge": ctx.node.badge},
        "hosts": s.hosts,
        "config_hashes": ctx.config.hashes,
        "keys": {k.name: k.public_key for k in ctx.signer.infos()},
        "log_head": {"index": head.index, "hash": head.hash},
        "tiers": {
            k: {"label": v.get("label", k), "ceiling_xe": v.get("ceiling_xe")}
            for k, v in ctx.config.tiers.items()
        },
        "endpoints": {
            "tickets": "/v1/tickets?kind=bounty&status=open&sort=severity",
            "ticket": "/v1/tickets/{id}",
            "thread": "/v1/tickets/{id}/thread",
            "leaderboard": "/v1/leaderboard",
            "log": "/v1/log",
            "log_head": "/v1/log/head",
            "log_verify": "/v1/log/verify",
            "events": "/v1/events?since={index}",
            "stream": "/v1/events/stream",
            "health": "/v1/health",
            "export": "/v1/export/triage.md",
            "scope": "/v1/scope",
            "openapi": "/v1/openapi.json",
            "agent": {
                "brief": "GET /v1/agent/brief.md",
                "fix": "GET /v1/agent/fix.md",
                "me": "GET /v1/me",
                "notes": "POST /v1/tickets/{id}/notes",
                "proposals": "POST /v1/tickets/{id}/proposals",
                "patch_refs": "POST /v1/tickets/{id}/patch-refs",
                "auth": "Authorization: Bearer desk_...",
            },
            "team": "/v1/team/*",
            "markdown": "append .md to any page, or Accept: text/markdown; /llms.txt",
        },
    }


@router.get("/scope")
async def scope(ctx: Ctx):
    return {
        "programme": ctx.config.programme,
        "copy": ctx.config.copy_programme,
        "areas": ctx.config.areas,
        "verdicts": ctx.config.verdicts,
        "gates": ctx.config.gates,
        "effort_bands": ctx.config.effort_bands,
    }


# ---- tickets ----------------------------------------------------------------------------------------


@router.get("/tickets")
async def list_tickets(
    ctx: Ctx,
    db: Db,
    who: Who,
    kind: str = "bounty",
    status: str = "open",
    area: str | None = None,
    verdict: str | None = None,
    gate: str | None = None,
    source: str | None = None,
    tier: str | None = None,
    has_pr: bool | None = None,
    has_internal: bool | None = None,
    pending: bool | None = None,
    q: str | None = None,
    reporter: int | None = None,
    queued: bool | None = None,
    sort: str = "severity",
    offset: int = 0,
    limit: int = Query(100, le=500),
):
    f = tsvc.Filters(
        kind=kind,
        status=status,
        area=area,
        verdict=verdict,
        gate=gate,
        source=source,
        tier=tier,
        has_pr=has_pr,
        has_internal=has_internal,
        pending=pending,
        q=q,
        reporter=reporter,
        queued=queued,
        sort=sort,
        offset=offset,
        limit=limit,
    )
    rows = await tsvc.list_tickets(db, ctx.config, who.principal, f)
    total = await tsvc.count_tickets(db, ctx.config, who.principal, f)
    ids = [t.id for t in rows]
    prs = await tsvc.patch_counts(db, ids)
    pend = await tsvc.pending_counts(db, ids) if who.principal.is_team or who.principal.is_agent else {}
    out = []
    for t in rows:
        d = tsvc.to_dict(ctx, t, who.principal)
        d["patch_refs"] = prs.get(t.id, 0)
        if pend:
            d["pending_proposals"] = pend.get(t.id, 0)
        out.append(d)
    # `total` is the whole selection; a reader that stops when offset + count < total has not read it all
    return {"tickets": out, "count": len(out), "offset": offset, "total": total}


@router.get("/tickets/counts")
async def ticket_counts(db: Db, who: Who, kind: str = "bounty"):
    return await tsvc.counts(db, who.principal, kind)


@router.get("/tickets/{tid}")
async def get_ticket(ctx: Ctx, db: Db, who: Who, tid: str):
    p = who.principal
    t = await tsvc.get_for(db, p, tid)
    d = tsvc.to_dict(ctx, t, p, with_body=True)
    if t.visibility == "private":
        await ctx.events.append(db, "ticket.read", p.actor, {"ticket": t.id}, ref=t.id, public=False)
        await db.commit()
    if t.duplicate_of and not can(p, "read:private"):
        dup = await tsvc.get(db, t.duplicate_of)
        if dup is not None and not can_see(p, dup):
            d["duplicate_of"] = None  # a private canonical is not named to one who cannot open it (XE-0799)
    d["patch_refs"] = [_patch(pr) for pr in await thread.patches_for(db, t)]
    d["thread"] = [_message(ctx, t, m) for m in await thread.messages_for(db, t)]
    if can(p, "read:notes", t):
        d["notes"] = [_note(n) for n in await thread.notes_for(db, t)]
        d["proposals"] = [psvc.to_dict(pr) for pr in await psvc.pending_for(db, t)]
    if p.is_team:
        d["replies"] = [_reply(ctx, r) for r in await thread.replies_for(db, t)]
    return d


@router.get("/tickets/{tid}/similar")
async def get_similar(ctx: Ctx, db: Db, who: Who, tid: str, limit: int = Query(10, le=30)):
    """What else on the desk looks like this ticket: shared words, shared source paths, the same reporter,
    duplicate links. The floor of the duplicate check; each row carries why it is there."""
    p = who.principal
    t = await tsvc.get_for(db, p, tid)
    body = tsvc.body_for(ctx, t) if t.visibility == "public" or can(p, "read:private", t) else ""
    if t.visibility == "private" and body:
        # the sealed body is opened to match on: "who has seen this" includes this route (XE-0734)
        payload = {"ticket": t.id, "what": "similar"}
        await ctx.events.append(db, "ticket.read", p.actor, payload, ref=t.id, public=False)
        await db.commit()
    rows = await tsvc.similar(db, ctx.config, p, t, body=body, limit=limit)
    return {"ticket": t.id, "similar": [tsvc.similar_dict(ctx, s, p, t) for s in rows]}


@router.get("/tickets/{tid}/thread")
async def get_thread(ctx: Ctx, db: Db, who: Who, tid: str):
    t = await tsvc.get_for(db, who.principal, tid)
    if t.visibility == "private":
        # sealed messages open here: "who has seen this" must include this route
        payload = {"ticket": t.id, "what": "thread"}
        await ctx.events.append(db, "ticket.read", who.principal.actor, payload, ref=t.id, public=False)
        await db.commit()
    return {"ticket": t.id, "messages": [_message(ctx, t, m) for m in await thread.messages_for(db, t)]}


@router.get("/tickets/{tid}/patch-refs")
async def get_patches(db: Db, who: Who, tid: str):
    t = await tsvc.get_for(db, who.principal, tid)
    return {"ticket": t.id, "patch_refs": [_patch(pr) for pr in await thread.patches_for(db, t)]}


def log_scope(p, t) -> dict:
    """How much of a ticket's log a principal sees: the team and its agents everything; the owning reporter
    of a private ticket the record of what happened to it (not notes, proposals, reasons or reads);
    everyone else the public events."""
    if can(p, "read:notes", t):
        return {"public_only": False}
    if can(p, "read:private", t):
        return {"public_only": False, "kinds": REPORTER_KINDS}
    return {"public_only": True}


def _ev(e, who: Who) -> dict:
    return event_to_dict(e, full=who.principal.is_team)


@router.get("/tickets/{tid}/log")
async def ticket_log(db: Db, who: Who, tid: str, offset: int = 0, limit: int = Query(100, le=500)):
    t = await tsvc.get_for(db, who.principal, tid)
    rows = await EventLog.page(db, offset, limit, ref=t.id, **log_scope(who.principal, t))
    return {"ticket": t.id, "events": [_ev(e, who) for e in rows]}


@router.get("/leaderboard")
async def leaderboard(db: Db):
    return {"leaderboard": await tsvc.leaderboard(db)}


@router.get("/export/triage.md", response_class=PlainTextResponse)
async def export_triage(ctx: Ctx, db: Db, who: Who):
    if not tsvc.sees_assessment(who.principal):
        raise HTTPException(403, "the triage export is the assessment of every open ticket; team and agents")
    text = await triage.export_markdown(ctx, db, who.principal)
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")


# ---- the log ----------------------------------------------------------------------------------------


@router.get("/log")
async def log_page(
    db: Db,
    who: Who,
    offset: int = 0,
    limit: int = Query(100, le=1000),
    kind: str | None = None,
    ref: str | None = None,
):
    rows = await EventLog.page(
        db, offset, limit, kind=kind, ref=ref, public_only=not can(who.principal, "read:private")
    )
    return {"events": [_ev(e, who) for e in rows], "offset": offset}


@router.get("/log/head")
async def log_head(db: Db):
    h = await EventLog.head(db)
    return {"index": h.index, "hash": h.hash}


@router.get("/log/verify")
@router.get("/events/verify")
async def log_verify(ctx: Ctx, db: Db):
    """Replays the whole chain: every hash recomputed, every signature checked against the published log
    key, head compared."""
    return await EventLog.verify(db, ctx.signer.public_key("log") if ctx.signer.has("log") else "")


@router.get("/log/{index}")
async def log_entry(db: Db, who: Who, index: int):
    ev = await EventLog.get(db, index)
    if ev is None or not (can(who.principal, "read:private") or await EventLog.served_public(db, ev)):
        raise HTTPException(404, "no such entry")
    return _ev(ev, who)


@router.get("/events")
async def events_since(db: Db, who: Who, since: int = -1, limit: int = Query(200, le=1000)):
    rows = await EventLog.since(db, since, limit, public_only=not can(who.principal, "read:private"))
    return {"events": [_ev(e, who) for e in rows], "next": rows[-1].index if rows else since}


@router.get("/events/stream")
async def events_stream(ctx: Ctx, request: Request, who: Who, since: int | None = None):
    """Server-sent events, one `entry` per log event. `since` (or Last-Event-ID) replays from an index."""
    private_ok = can(who.principal, "read:private")
    full = who.principal.is_team
    start = since
    if start is None:
        hdr = request.headers.get("last-event-id")
        start = int(hdr) if hdr and hdr.lstrip("-").isdigit() else None

    async def gen():
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        last = start
        async with session() as db:
            if last is not None:
                for ev in await EventLog.since(db, last, 1000, public_only=not private_ok):
                    d = event_to_dict(ev, full=full)
                    yield {"event": "entry", "id": str(ev.index), "data": json.dumps(d)}
                    last = ev.index
            else:
                last = (await EventLog.head(db)).index
        ctx.events.subscribe(queue)
        try:
            while True:
                if await request.is_disconnected():
                    return
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    # the worker writes to the same log from another process; catch up on its entries
                    if last is not None:
                        async with session() as db:
                            for ev in await EventLog.since(db, last, 200, public_only=not private_ok):
                                last = ev.index
                                yield {
                                    "event": "entry",
                                    "id": str(ev.index),
                                    "data": json.dumps(event_to_dict(ev, full=full)),
                                }
                    yield {"event": "ping", "data": str(int(time.time()))}
                    continue
                d = ev if isinstance(ev, dict) else event_to_dict(ev, full=full)
                if last is not None and d["index"] <= last:
                    continue
                if not d.get("public", True) and not private_ok:
                    continue
                last = d["index"]
                yield {"event": "entry", "id": str(d["index"]), "data": json.dumps(d)}
        finally:
            ctx.events.unsubscribe(queue)

    return EventSourceResponse(gen())


# ---- health -----------------------------------------------------------------------------------------


HEALTH_MAX_AGE_NS = 15 * 60 * 1_000_000_000  # three missed five-minute checks


@router.get("/health")
async def health(ctx: Ctx, db: Db):
    head = await EventLog.head(db)
    last = (
        await db.execute(select(HealthCheck).order_by(HealthCheck.ts.desc()).limit(1))
    ).scalar_one_or_none()
    # the verdict is the worker's last word, and only while it is fresh: a dead worker is not ok (XE-1443)
    fresh = last is not None and time.time_ns() - last.ts < HEALTH_MAX_AGE_NS
    return {
        "ok": bool(fresh and last.ok),
        "worker_fresh": fresh,
        "version": __version__,
        "git_commit": ctx.settings.git_commit,
        "network_id": ctx.node.network_id,
        "log_head": head.index,
        "vault": ctx.vault.available,
        "signer": ctx.signer.has("log"),
        "worker": {"ts": last.ts, "ok": last.ok, "detail": last.detail} if last else None,
    }


# ---- github webhook ---------------------------------------------------------------------------------


@router.post("/github/webhook", include_in_schema=False)
async def github_webhook(ctx: Ctx, db: Db, request: Request):
    body = await request.body()
    if not gh.verify_webhook(
        ctx.settings.github_webhook_secret, body, request.headers.get("x-hub-signature-256", "")
    ):
        raise HTTPException(401, "bad signature")
    delivery = request.headers.get("x-github-delivery", "")
    event = request.headers.get("x-github-event", "")
    if delivery:
        if (await db.execute(select(SeenDelivery).where(SeenDelivery.id == delivery))).scalar_one_or_none():
            return {"ok": True, "duplicate": True}
        db.add(SeenDelivery(id=delivery))
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(400, "not json") from None
    result = await sync.handle_webhook(ctx, db, event, payload)
    await db.commit()
    return {"ok": True, **result}


# ---- shapes -----------------------------------------------------------------------------------------


def _patch(pr) -> dict:
    return {
        "id": pr.id,
        "repo": pr.repo,
        "kind": pr.kind,
        "ref": pr.ref,
        "title": pr.title,
        "url": pr.url,
        "note": pr.note,
        "state": pr.state,
        "author": pr.author,
        "added_by": pr.added_by,
        "created_at": thread.iso(pr.created_at),
    }


def _message(ctx, t, m) -> dict:
    return {
        "id": m.id,
        "source": m.source,
        "source_ref": m.source_ref,
        "author": m.author,
        "team": m.author_is_team,
        "body": thread.message_body(ctx, t, m),
        "created_at": thread.iso(m.created_at),
    }


def _note(n) -> dict:
    return {
        "id": n.id,
        "author": n.author,
        "author_name": n.author_name,
        "body": n.body,
        "checked": n.checked,
        "created_at": thread.iso(n.created_at),
    }


def _reply(ctx, r) -> dict:
    return {
        "id": r.id,
        "author_id": r.author_id,
        "author_name": r.author_name,
        "body": thread.reply_body(ctx, r),
        "mirror": r.mirror,
        "mirror_ref": r.mirror_ref,
        "mirror_error": r.mirror_error,
        "created_at": thread.iso(r.created_at),
        "sent_at": thread.iso(r.sent_at),
    }

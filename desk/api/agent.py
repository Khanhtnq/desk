"""What an agent token can do: read what its scopes allow, write notes, propose, link patches. There is
no route here that sets a fact, sends a reply or changes a status; those are in team.py and reject
tokens in the authorisation layer."""

from __future__ import annotations

import math
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import Field

from ..authz import require
from ..brief import build_agent_brief, fix_brief
from ..services import proposals as psvc
from ..services import thread, users
from ..services import tickets as tsvc
from ..ui import site_for, site_url
from .deps import Body, Ctx, Db, Who

router = APIRouter(prefix="/v1", tags=["agent"])


class NoteIn(Body):
    body: str = Field(min_length=1, max_length=20_000)
    # what was looked at before writing:
    # {"desk": 692, "similar": ["XE-0130"], "tracker": true, "tree": "xe@abc1234"}
    checked: dict[str, Any] | None = None


class ProposalIn(Body):
    field: str
    value: Any
    reason: str = Field(default="", max_length=4000)


class PatchIn(Body):
    repo: str = Field(default="", max_length=128)
    ref: str = Field(max_length=64)
    kind: str = Field(default="pr", max_length=8)
    title: str = Field(default="", max_length=512)
    url: str = Field(default="", max_length=512)
    note: str = Field(default="", max_length=128)


def _storable(v: Any, depth: int = 0) -> None:
    """A proposal value goes into JSONB: finite numbers and bounded nesting (XE-1015). A NUL in it
    never gets here: `auth.Body` has refused the request."""
    if depth > 8:
        raise HTTPException(400, "the value is nested too deep")
    if isinstance(v, float) and not math.isfinite(v):
        raise HTTPException(400, "the value has a non-finite number in it")
    if isinstance(v, dict):
        for k, x in v.items():
            _storable(k, depth + 1)
            _storable(x, depth + 1)
    elif isinstance(v, list):
        for x in v:
            _storable(x, depth + 1)


@router.get("/tickets/{tid}/notes")
async def list_notes(db: Db, who: Who, tid: str):
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "read:notes", t)
    return {
        "ticket": t.id,
        "notes": [
            {
                "id": n.id,
                "author": n.author,
                "author_name": n.author_name,
                "body": n.body,
                "checked": n.checked,
                "created_at": thread.iso(n.created_at),
            }
            for n in await thread.notes_for(db, t)
        ],
    }


@router.post("/tickets/{tid}/notes", status_code=201)
async def add_note(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: NoteIn):
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "write:notes", t)
    n = await thread.add_note(ctx, db, who.principal, t, body.body, body.checked)
    await db.commit()
    return {"id": n.id, "ticket": t.id, "created_at": thread.iso(n.created_at)}


@router.get("/tickets/{tid}/proposals")
async def list_proposals(db: Db, who: Who, tid: str):
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "read:notes", t)
    return {"ticket": t.id, "proposals": [psvc.to_dict(pr) for pr in await psvc.pending_for(db, t)]}


@router.post("/tickets/{tid}/proposals", status_code=201)
async def propose(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: ProposalIn):
    _storable(body.value)
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "write:proposals", t)
    pr = await psvc.propose(ctx, db, who.principal, t, body.field, body.value, body.reason)
    await db.commit()
    return psvc.to_dict(pr, who.principal.token)


@router.post("/tickets/{tid}/proposals/bulk", status_code=201)
async def propose_bulk(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: list[ProposalIn]):
    """Several fields at once, one transaction; the usual shape after reading a new ticket."""
    if len(body) > 12:
        raise HTTPException(400, "at most 12 proposals per call")
    for b in body:
        _storable(b.value)
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "write:proposals", t)
    out = [
        psvc.to_dict(
            await psvc.propose(ctx, db, who.principal, t, b.field, b.value, b.reason), who.principal.token
        )
        for b in body
    ]
    await db.commit()
    return {"proposals": out}


@router.post("/tickets/{tid}/patch-refs", status_code=201)
async def add_patch(ctx: Ctx, db: Db, who: Who, request: Request, tid: str, body: PatchIn):
    t = await tsvc.get_for(db, who.principal, tid)
    require(who.principal, "write:patch-refs", t)
    repo, ref = body.repo, body.ref
    if not repo:
        parsed = thread.parse_patch_token(ref, ctx.config.primary_repo)
        if parsed is None:
            raise HTTPException(400, "give repo and ref, or a token like #27, dao#1, owner/repo#5")
        repo, ref = parsed
    pr = await thread.add_patch_ref(
        ctx,
        db,
        who.principal,
        t,
        repo=repo,
        ref=ref,
        kind=body.kind,
        title=body.title,
        url=body.url,
        note=body.note,
    )
    await db.commit()
    if pr is None:
        return {"ticket": t.id, "unchanged": True}
    return {"ticket": t.id, "id": pr.id, "repo": pr.repo, "ref": pr.ref, "url": pr.url}


async def _brief(ctx: Ctx, db: Db, who: Who, request: Request) -> str:
    """The general brief; with a token, its own section (scopes, owner, standing instructions) on top."""
    p = who.principal
    owner = ""
    if p.token:
        owner = (await users.token_owners(db)).get(p.token.id, "")
    return build_agent_brief(
        ctx.config, site_url(ctx, site_for(request)), ctx.node.network_id, token=p.token, owner=owner
    )


@router.get("/agent/brief.md", response_class=PlainTextResponse)
async def agent_brief_md(ctx: Ctx, db: Db, who: Who, request: Request):
    return PlainTextResponse(await _brief(ctx, db, who, request), media_type="text/markdown; charset=utf-8")


@router.get("/agent/fix.md", response_class=PlainTextResponse)
async def agent_fix_md():
    """How a report becomes a fix, for whoever takes the engineering ticket. Public; no token needed."""
    return PlainTextResponse(fix_brief(), media_type="text/markdown; charset=utf-8")


@router.get("/agent/brief")
async def agent_brief(ctx: Ctx, db: Db, who: Who, request: Request):
    p = who.principal
    return {
        "brief": await _brief(ctx, db, who, request),
        "format": "markdown",
        "config_hashes": ctx.config.hashes,
        "instructions": p.token.instructions if p.token else "",
    }


@router.get("/me")
async def me(who: Who):
    p = who.principal
    out: dict[str, Any] = {"kind": p.kind, "actor": p.actor, "name": p.name, "brief": "/v1/agent/brief.md"}
    if p.token:
        out["token"] = {
            "id": p.token.id,
            "model_id": p.token.model_id,
            "label": p.token.label,
            "scopes": p.token.scopes,
            "instructions": p.token.instructions,
            "expires_at": thread.iso(p.token.expires_at),
        }
    if p.user:
        out["user"] = {"id": p.user.id, "email": p.user.email, "roles": sorted(p.roles)}
    return out

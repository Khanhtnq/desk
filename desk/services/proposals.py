"""Proposals: an agent's suggested change to a ticket fact, pending until a human adopts or rejects it.

Adopting writes the field through the same code path a human edit uses (so vocabulary and permission
checks apply) and records who adopted what, proposed by which token. A `reply_draft` proposal is
never written anywhere: adopting it hands the text to the reply editor.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import Principal, can, require, require_field
from ..context import Context
from ..models import PROPOSAL_FIELDS, AgentToken, Proposal, Ticket
from . import tickets as tsvc
from .tickets import utcnow


async def propose(
    ctx: Context, db: AsyncSession, p: Principal, t: Ticket, field: str, value: Any, reason: str
) -> Proposal:
    if field not in PROPOSAL_FIELDS:
        raise HTTPException(400, f"field must be one of {list(PROPOSAL_FIELDS)}")
    if p.token is None:
        raise HTTPException(403, "proposals come from agent tokens; a person sets the fact directly")
    if field == "status" and not isinstance(value, (str, dict)):
        raise HTTPException(400, "status proposals are a string or {status, closed_reason}")
    if field == "reply_draft" and not isinstance(value, str):
        raise HTTPException(400, "a reply draft is a string")
    if field == "award_xe":
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HTTPException(400, "award_xe is a whole number of XE, 0 or more")
        ceiling = ctx.config.ceiling_micro(t.assessed_tier) // 1_000_000
        if ceiling and value > ceiling * 2:
            raise HTTPException(400, f"award_xe exceeds twice the {t.assessed_tier} ceiling ({ceiling} XE)")
        if not reason or len(reason.strip()) < 20:
            raise HTTPException(400, "an award proposal needs a reason of at least 20 characters")
    # collapse a repeat proposal from the same token on the same field
    q = select(Proposal).where(
        Proposal.ticket_id == t.id,
        Proposal.token_id == p.token.id,
        Proposal.field == field,
        Proposal.state == "pending",
    )
    for old in (await db.execute(q)).scalars().all():
        old.state = "superseded"
        old.decided_at = utcnow()
    pr = Proposal(
        ticket_id=t.id, token_id=p.token.id, field=field, value={"value": value}, reason=(reason or "")[:4000]
    )
    db.add(pr)
    await db.flush()
    payload = {
        "ticket": t.id,
        "proposal": pr.id,
        "field": field,
        "token": p.token.id,
        "model": p.token.model_id,
    }
    if field != "reply_draft":
        payload["value"] = value
    await ctx.events.append(
        db, "proposal.created", p.actor, payload, ref=t.id, public=t.visibility == "public"
    )
    return pr


async def pending_field_for(db: AsyncSession, ticket_ids: list[str], field: str) -> dict[str, list[Proposal]]:
    """Pending proposals on one field across many tickets, newest first per ticket (the awards page)."""
    if not ticket_ids:
        return {}
    q = (
        select(Proposal)
        .where(Proposal.ticket_id.in_(ticket_ids), Proposal.field == field, Proposal.state == "pending")
        .order_by(Proposal.created_at.desc())
    )
    out: dict[str, list[Proposal]] = {}
    for pr in (await db.execute(q)).scalars().all():
        out.setdefault(pr.ticket_id, []).append(pr)
    return out


async def pending_for(db: AsyncSession, t: Ticket) -> list[Proposal]:
    q = select(Proposal).where(Proposal.ticket_id == t.id).order_by(Proposal.created_at.desc())
    return list((await db.execute(q)).scalars().all())


async def get(db: AsyncSession, pid: int) -> Proposal | None:
    return (await db.execute(select(Proposal).where(Proposal.id == pid))).scalar_one_or_none()


async def decide(
    ctx: Context, db: AsyncSession, p: Principal, pr: Proposal, adopt: bool, *, reason: str = ""
) -> dict:
    """Adopt or reject. Returns what happened, including a reply draft when that is what was adopted."""
    if pr.state != "pending":
        raise HTTPException(409, f"proposal is already {pr.state}")
    if p.user is None or not can(p, "adopt"):
        raise HTTPException(403, "adopting is a reviewer's action")
    t = await tsvc.get(db, pr.ticket_id)
    if t is None:
        raise HTTPException(404, "ticket is gone")
    out: dict[str, Any] = {"proposal": pr.id, "ticket": t.id, "field": pr.field, "adopted": adopt}
    value = pr.value.get("value")
    if adopt:
        if pr.field == "reply_draft":
            out["reply_draft"] = value
        elif pr.field == "status":
            status = value if isinstance(value, str) else value.get("status")
            reason_c = None if isinstance(value, str) else value.get("closed_reason")
            require_field(p, "status")
            # an agent may propose a status several hops away; the desk walks the allowed path, one
            # logged hop at a time, inside this transaction
            out["path"] = await tsvc.set_status_via_path(
                ctx, db, p, t, status, closed_reason=reason_c, reason=reason, via=f"proposal:{pr.id}"
            )
            out["status"] = t.status
        elif pr.field == "award_xe":
            # sets the amount only; approval stays a separate, deliberate click
            require(p, "award", t)
            await tsvc.set_award(ctx, db, p, t, int(value) * 1_000_000)
            out["award_xe"] = int(value) * 1_000_000
        else:
            require_field(p, pr.field)
            out["diff"] = await tsvc.set_facts(
                ctx, db, p, t, {pr.field: value}, reason=reason, via=f"proposal:{pr.id}"
            )
    pr.state = "adopted" if adopt else "rejected"
    pr.decided_by = p.user.id
    pr.decided_at = utcnow()
    await ctx.events.append(
        db,
        "proposal.adopted" if adopt else "proposal.rejected",
        p.actor,
        {
            "ticket": t.id,
            "proposal": pr.id,
            "field": pr.field,
            "reason": reason[:500],
        },
        ref=t.id,
        public=t.visibility == "public",
    )
    return out


def to_dict(pr: Proposal, token: AgentToken | None = None) -> dict:
    return {
        "id": pr.id,
        "ticket": pr.ticket_id,
        "field": pr.field,
        "value": pr.value.get("value"),
        "reason": pr.reason,
        "state": pr.state,
        "token_id": pr.token_id,
        "model": token.model_id if token else None,
        "created_at": pr.created_at.isoformat() if pr.created_at else None,
        "decided_by": pr.decided_by,
        "decided_at": pr.decided_at.isoformat() if pr.decided_at else None,
    }

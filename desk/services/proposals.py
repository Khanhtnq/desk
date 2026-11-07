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
from ..config import Config
from ..context import Context
from ..models import PROPOSAL_FIELDS, AgentToken, Note, Proposal, Ticket
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
            # filled and kept on the ticket until a reply is sent; the browser's editor is not the only copy
            from . import thread

            t.draft = out["reply_draft"] = thread.fill(ctx, str(value), t)
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


async def pending_duplicates_of(db: AsyncSession, tid: str) -> list[tuple[Ticket, Proposal]]:
    """Open tickets carrying a pending `duplicate_of` proposal that names `tid`: the family an agent has
    read as re-filings of this one, waiting for a ruling."""
    q = (
        select(Ticket, Proposal)
        .join(Proposal, Proposal.ticket_id == Ticket.id)
        .where(
            Proposal.field == "duplicate_of",
            Proposal.state == "pending",
            Proposal.value["value"].astext == tid,
            Ticket.status != "closed",
            Ticket.id != tid,
        )
        .order_by(Ticket.id)
    )
    return [(t, pr) for t, pr in (await db.execute(q)).all()]


async def close_duplicates(
    ctx: Context, db: AsyncSession, p: Principal, canon: Ticket, only: list[str] | None = None
) -> dict:
    """Rule a whole family at once. For every open ticket with a pending `duplicate_of` proposal naming
    `canon`: adopt it, set the verdict, close as duplicate (walking the status path), and send the
    programme's own duplicate reply under the person ruling. Each ticket is its own savepoint, so one the
    desk refuses (a transition, a permission) is reported and left as it was while the rest go through.
    The decision stays a person's: this is one click for a family instead of four per ticket."""
    from . import thread

    if p.user is None or not can(p, "adopt"):
        raise HTTPException(403, "adopting is a reviewer's action")
    require_field(p, "duplicate_of")
    require_field(p, "status")
    closed: list[dict] = []
    skipped: list[dict] = []
    for t, pr in await pending_duplicates_of(db, canon.id):
        if only and t.id not in only:
            continue
        tid = t.id  # read before the savepoint: a rollback expires the row and a lazy load here is a 500
        try:
            async with db.begin_nested():
                require(p, "reply", t)
                why = f"duplicate of {canon.id}"
                via = f"family:{canon.id}"
                await decide(ctx, db, p, pr, True, reason=why)
                others = {o.field: o for o in await pending_for(db, t) if o.state == "pending"}
                v = others.get("verdict")
                if v is not None and v.value.get("value") == "duplicate":
                    await decide(ctx, db, p, v, True, reason=why)
                elif t.verdict != "duplicate":
                    await tsvc.set_facts(ctx, db, p, t, {"verdict": "duplicate"}, reason=why, via=via)
                s = others.get("status")
                sv = s.value.get("value") if s is not None else None
                is_dup_close = isinstance(sv, dict) and (sv.get("status"), sv.get("closed_reason")) == (
                    "closed",
                    "duplicate",
                )
                if is_dup_close:
                    await decide(ctx, db, p, s, True, reason=why)
                else:
                    await tsvc.set_status_via_path(
                        ctx, db, p, t, "closed", closed_reason="duplicate", reason=why, via=via
                    )
                d = others.get("reply_draft")
                if d is not None:
                    await decide(ctx, db, p, d, True)  # recorded as adopted; the reply below clears the draft
                text = thread.render_template(ctx, "duplicate", t)
                r = await thread.add_reply(ctx, db, p, t, text)
                closed.append({"ticket": tid, "status": t.status, "reply": r.id, "text": text})
        except HTTPException as e:
            skipped.append({"ticket": tid, "why": str(e.detail)})
    return {"canonical": canon.id, "closed": closed, "skipped": skipped}


async def decide_many(
    ctx: Context, db: AsyncSession, p: Principal, adopt: list[int], reject: list[int]
) -> dict:
    """Many decisions in one request, each its own savepoint: one the desk refuses (a transition the
    state machine will not make, a field the role may not set) is reported in `skipped` and the rest go
    through. A batch that stopped at the first refusal left a reviewer adopting one by one (XE-0872)."""
    if p.user is None or not can(p, "adopt"):
        raise HTTPException(403, "adopting is a reviewer's action")
    decided: list[dict] = []
    skipped: list[dict] = []
    for pid, yes in [(i, True) for i in adopt] + [(i, False) for i in reject]:
        pr = await get(db, pid)
        if pr is None or pr.state != "pending":
            skipped.append({"proposal": pid, "why": "not pending" if pr else "no such proposal"})
            continue
        tid, field = pr.ticket_id, pr.field  # read before the savepoint (see close_duplicates)
        try:
            async with db.begin_nested():
                decided.append(await decide(ctx, db, p, pr, yes))
        except HTTPException as e:
            skipped.append({"proposal": pid, "ticket": tid, "field": field, "why": str(e.detail)})
    return {"decided": decided, "skipped": skipped}


# ---- the triage page ---------------------------------------------------------------------------------
#
# One row per ticket with something pending, the pending set rendered as chips, the agent's latest note
# beside it. The views are the questions a reviewer asks in turn: what is a duplicate, what closes, what
# is a real finding, what gets paid, what gets a reply.

TRIAGE_VIEWS = ("all", "duplicates", "closures", "assessments", "awards", "replies")
ASSESSMENT_FIELDS = ("verdict", "assessed_tier", "mainnet_gate", "effort_eng", "area", "internal_ref")


def _is_close(pr: Proposal) -> bool:
    """A status proposal that closes for any reason but duplicate. The value is a string or a dict."""
    if pr.field != "status":
        return False
    v = pr.value.get("value")
    if isinstance(v, dict):
        return v.get("status") == "closed" and v.get("closed_reason") != "duplicate"
    return v == "closed"


def triage_views(prs: list[Proposal]) -> set[str]:
    """Which views a ticket's pending set belongs to. A duplicate is only a duplicate; a closure is only a
    closure; anything else with an assessment field is an assessment. Awards and replies cut across."""
    fields = {pr.field for pr in prs}
    out: set[str] = set()
    if "duplicate_of" in fields:
        out.add("duplicates")
    elif any(_is_close(pr) for pr in prs):
        out.add("closures")
    elif fields & set(ASSESSMENT_FIELDS):
        out.add("assessments")
    if "award_xe" in fields:
        out.add("awards")
    if "reply_draft" in fields:
        out.add("replies")
    return out


def proposed_tier(t: Ticket, prs: list[Proposal]) -> str | None:
    """The tier the row sorts and filters on: the pending proposal if there is one, else the ruling."""
    for pr in prs:
        if pr.field == "assessed_tier":
            return str(pr.value.get("value"))
    return t.assessed_tier


class TriageRow:
    __slots__ = ("ticket", "proposals", "views", "tier", "note", "canonical", "mine", "klass")

    def __init__(self, t: Ticket, prs: list[Proposal]):
        self.ticket = t
        self.proposals = prs
        self.views: set[str] = set()
        self.tier: str | None = None
        self.note: Note | None = None
        self.canonical: Ticket | None = None
        self.mine: list[int] = []  # the proposal ids the viewer's roles let them adopt; set by the page
        self.klass: list[Ticket] = []  # the other reports on the same engineering ticket

    @property
    def duplicate_of(self) -> str | None:
        for pr in self.proposals:
            if pr.field == "duplicate_of":
                return str(pr.value.get("value"))
        return None


async def triage_rows(
    db: AsyncSession,
    cfg: Config,
    p: Principal,
    *,
    kind: str = "bounty",
    view: str = "all",
    area: str | None = None,
    tier: str | None = None,
    reporter: int | None = None,
) -> list[TriageRow]:
    """Every visible ticket with pending proposals, as rows. Filtering by view, area, proposed tier and
    reporter; ordered most severe first, then newest proposal first. The counts per view come from the
    unfiltered set, so the chips say what is waiting everywhere, not only on the page shown."""
    q = (
        select(Ticket, Proposal)
        .join(Proposal, Proposal.ticket_id == Ticket.id)
        .where(Proposal.state == "pending", Ticket.kind == kind)
        .order_by(Proposal.created_at.desc(), Proposal.id.desc())
    )
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    if area:
        q = q.where(Ticket.area == area)
    if reporter is not None:
        q = q.where(Ticket.reporter_id == reporter)
    by_ticket: dict[str, TriageRow] = {}
    for t, pr in (await db.execute(q)).all():
        row = by_ticket.get(t.id)
        if row is None:
            row = by_ticket[t.id] = TriageRow(t, [])
        row.proposals.append(pr)
    rows = list(by_ticket.values())
    for row in rows:
        row.views = triage_views(row.proposals)
        row.tier = proposed_tier(row.ticket, row.proposals)
    if view != "all":
        rows = [r for r in rows if view in r.views]
    if tier:
        rows = [r for r in rows if r.tier == tier]
    # rows arrive newest proposal first; a stable sort by tier keeps that order within each tier
    order = {t: i for i, t in enumerate(cfg.tier_order)}
    rows.sort(key=lambda r: order.get(r.tier or "", len(order)))
    ids = [r.ticket.id for r in rows]
    if ids:
        nq = (
            select(Note)
            .where(Note.ticket_id.in_(ids), Note.author.like("token:%"))
            .order_by(Note.created_at.desc(), Note.id.desc())  # one transaction shares a now()
        )
        notes: dict[str, Note] = {}
        for n in (await db.execute(nq)).scalars().all():
            notes.setdefault(n.ticket_id, n)
        canon_ids = {r.duplicate_of for r in rows if r.duplicate_of}
        canons = {
            c.id: c
            for c in (await db.execute(select(Ticket).where(Ticket.id.in_(canon_ids)))).scalars().all()
        } if canon_ids else {}
        refs = {r.ticket.internal_ref for r in rows if r.ticket.internal_ref}
        by_ref = await tsvc.same_class(db, p, refs) if refs else {}
        for r in rows:
            r.note = notes.get(r.ticket.id)
            r.canonical = canons.get(r.duplicate_of or "")
            r.klass = [o for o in by_ref.get(r.ticket.internal_ref, []) if o.id != r.ticket.id]
    return rows


async def triage_counts(db: AsyncSession, p: Principal, kind: str = "bounty") -> dict[str, int]:
    """How many tickets wait in each view, over everything visible, for the chips."""
    q = select(Ticket.id, Proposal).join(Proposal, Proposal.ticket_id == Ticket.id)
    q = q.where(Proposal.state == "pending", Ticket.kind == kind)
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    by_ticket: dict[str, list[Proposal]] = {}
    for tid, pr in (await db.execute(q)).all():
        by_ticket.setdefault(tid, []).append(pr)
    counts = {v: 0 for v in TRIAGE_VIEWS}
    counts["all"] = len(by_ticket)
    counts["proposals"] = sum(len(v) for v in by_ticket.values())
    for prs in by_ticket.values():
        for v in triage_views(prs):
            counts[v] += 1
    return counts


def note_excerpt(n: Note | None, limit: int = 240) -> str:
    """The agent's claim, for the row: the first paragraph of its note with the bold label stripped."""
    if n is None:
        return ""
    first = (n.body or "").strip().split("\n", 1)[0]
    first = first.replace("**Claim.**", "").replace("**Claim:**", "").strip()
    return first if len(first) <= limit else first[: limit - 1].rstrip() + "…"


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

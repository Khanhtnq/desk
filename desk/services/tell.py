"""The desk tells a reporter what nobody has. A bounty ticket that comes to rest at `accepted` or `patched`
and stays there, untold, past a grace period is sent the programme's stock reply for that status, signed
by the desk (`thread.DESK_NAME`). The reply goes the way every reply goes: onto the thread, out through
the ticket's own channel, and by mail once the worker has committed (`notify.owe`).

The rule lives in one sweep over state (`tell_resting`, run by the worker) rather than in `set_status`,
so it holds whatever moved the ticket (a person, an adopted proposal, a merged PR, the internal tracker)
and a ticket walked through `accepted` on its way to `patched` is told once, about where it stopped.

What the desk leaves to a person, and so to the outbox:
- anything a person has in hand: a reply sent since the move (`told_at`), a draft saved on the ticket,
  an agent's reply draft waiting to be adopted;
- a `patched` ticket with no patch the desk may name on its own (`nameable`): the words are "fixed in
  ...", and a stranger's unmerged PR that says "Fixes #N" is not where it was fixed (XE-0128);
- a move back (`fixing` to `accepted`: the fix was withdrawn), which "read and accepted" does not fit;
- a bulk triage import, and every move made before this sweep first ran: the backlog is not swept;
- a private ticket while the vault key is not loaded.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import SYSTEM
from ..context import Context
from ..models import Event, PatchRef, Proposal, Ticket
from . import notify, sync, thread
from . import tickets as tsvc

log = logging.getLogger("desk.tell")

TELLS = ("accepted", "patched")  # each has a reply template of the same name
GRACE = timedelta(minutes=15)  # a person's own words come first; this is how long the desk waits for them
CURSOR = "tell:since"  # when the sweep first ran; a move from before it is the outbox's
BATCH = 50  # replies in one run; the rest go on the next
BEFORE_ACCEPTED = ("new", "triaging", "needs-info")


def nameable(pr: PatchRef) -> bool:
    """A patch the desk may name as the fix without a person reading it first: anything except a PR the
    sync linked off GitHub that GitHub does not call merged. Whoever opens a PR saying "Fixes #N" gets it
    linked; only a merge, or a person or the team's agent linking it, makes it the fix."""
    return not (pr.added_by == SYSTEM.actor and pr.state in ("open", "closed"))


async def words(ctx: Context, db: AsyncSession, t: Ticket, moved: dict | None) -> str:
    """The stock reply for where `t` rests, or "" when the desk has none it may send. `moved` is the
    payload of the ticket's latest `ticket.status` event."""
    tpl = ctx.config.reply_templates.get(t.status, "")
    if t.status not in TELLS or not tpl.strip() or moved is None:
        return ""
    if moved.get("to") != t.status or moved.get("via") == "triage":
        return ""
    if t.status == "accepted":
        return await thread.fill_for(ctx, db, tpl, t) if moved.get("from") in BEFORE_ACCEPTED else ""
    refs = thread.patch_refs_text([p for p in await thread.patches_for(db, t) if nameable(p)])
    return await thread.fill_for(ctx, db, tpl, t, patch_refs=refs) if refs else ""


async def tell_resting(ctx: Context, db: AsyncSession, *, now: datetime | None = None) -> list[dict]:
    """Send the stock reply on every ticket the rule above covers. Each ticket is its own savepoint
    under the ticket's row lock, re-read before anything is sent, so a reply or a status move that
    landed a moment ago wins and one ticket the desk refuses does not stop the rest. Returns what was
    sent, `{"ticket", "status", "reply"}` each; the caller commits and then mails (`notify.take_owed`)."""
    now = now or tsvc.utcnow()
    since = await sync.get_cursor(db, CURSOR)
    if not since:
        await sync.set_cursor(db, CURSOR, now.isoformat())
        return []
    q = select(Ticket).where(
        Ticket.kind == "bounty",
        Ticket.status.in_(TELLS),
        Ticket.status_changed_at > datetime.fromisoformat(since),
        Ticket.status_changed_at <= now - GRACE,
        tsvc.UNTOLD,
        Ticket.draft == "",
    )
    if not ctx.vault.available:
        q = q.where(Ticket.visibility == "public")  # a reply on a private ticket is sealed
    resting = list((await db.execute(q.order_by(Ticket.status_changed_at.asc()))).scalars().all())
    if not resting:
        return []
    ids = [t.id for t in resting]
    drafted = set(
        (
            await db.execute(
                select(Proposal.ticket_id).where(
                    Proposal.ticket_id.in_(ids), Proposal.field == "reply_draft", Proposal.state == "pending"
                )
            )
        ).scalars()
    )
    ev = select(Event.ref, Event.payload).where(Event.kind == "ticket.status", Event.ref.in_(ids))
    moves = {ref: payload for ref, payload in (await db.execute(ev.order_by(Event.index.asc()))).all()}
    told: list[dict] = []
    for t in resting:
        if len(told) >= BATCH:
            break
        # read before the savepoint: a rollback expires the row, and a lazy load after it is an error
        tid, status, moved_at = t.id, t.status, t.status_changed_at
        if tid in drafted:
            continue
        try:
            text = await words(ctx, db, t, moves.get(tid))
            if not text:
                continue
            async with db.begin_nested():
                await tsvc.lock(db, t)
                if t.status_changed_at != moved_at or not tsvc.untold(t) or t.draft:
                    continue  # it moved, or a person got there first, while this was being read
                r = await thread.add_reply(ctx, db, SYSTEM, t, text)
                notify.owe(db, r)
                told.append({"ticket": tid, "status": status, "reply": r.id})
        except HTTPException as e:
            log.warning("%s at %s not told: %s", tid, status, e.detail)
    return told

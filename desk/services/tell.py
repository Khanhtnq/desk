"""The desk tells a reporter what nobody has. A bounty ticket that comes to rest at `accepted` or `patched`
and stays there, untold, past a grace period is sent the programme's stock reply for that status, signed
by the desk (`thread.DESK_NAME`). The reply goes the way every reply goes: onto the thread, out through
the ticket's own channel, and by mail once the worker has committed (`notify.owe`).

The rule lives in one sweep over state (`tell_resting`, run by the worker) rather than in `set_status`,
so it holds whatever moved the ticket (a person, an adopted proposal, a merged PR, the internal tracker)
and a ticket walked through `accepted` on its way to `patched` is told once, about where it stopped.
`resting` is the rule itself: every ticket it covers, with the reply it would be sent or the reason it
is left. The worker and the backlog command both send exactly what it lists.

What the desk leaves to a person, and so to the outbox:
- anything a person has in hand: a reply sent since the move (`told_at`), a draft saved on the ticket,
  an agent's reply draft waiting to be adopted;
- a `patched` ticket with no patch the desk may name on its own (`nameable`): the words are "fixed in
  ...", and a stranger's unmerged PR that says "Fixes #N" is not where it was fixed (XE-0128);
- a move back (`fixing` to `accepted`: the fix was withdrawn), which "read and accepted" does not fit;
- a bulk triage import;
- a private ticket while the vault key is not loaded.

The worker tells only moves made since it first ran this (cursor `tell:since`), so switching it on
sends nothing by itself. What was already resting then is swept by hand, once, with the same rule:
`desk tell-backlog --dry-run` to read what would go, `desk tell-backlog` to send it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
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
CURSOR = "tell:since"  # when the worker first ran the sweep; a move from before it is the backlog's
BATCH = 50  # replies in one run; the rest go on the next
BEFORE_ACCEPTED = ("new", "triaging", "needs-info")


def nameable(pr: PatchRef) -> bool:
    """A patch the desk may name as the fix without a person reading it first: anything except a PR the
    sync linked off GitHub that GitHub does not call merged. Whoever opens a PR saying "Fixes #N" gets it
    linked; only a merge, or a person or the team's agent linking it, makes it the fix."""
    return not (pr.added_by == SYSTEM.actor and pr.state in ("open", "closed"))


@dataclass
class Resting:
    """An untold ticket at a status the desk tells: the reply it would be sent (`text`), or why the
    desk leaves it to a person (`why`). The row's own facts are copied out when it is read, so they are
    still there after a savepoint elsewhere in the sweep has rolled back."""

    ticket: Ticket
    id: str
    status: str
    moved_at: datetime
    text: str = ""
    why: str = ""


async def _reply_for(
    ctx: Context, db: AsyncSession, t: Ticket, moved: dict | None, drafted: bool
) -> tuple[str, str]:
    """The stock reply for where `t` rests, or "" and why the desk has none it may send. `moved` is
    the payload of the ticket's latest `ticket.status` event; `drafted`, whether an agent's reply draft
    is waiting on it."""
    tpl = ctx.config.reply_templates.get(t.status, "")
    if t.status not in TELLS or not tpl.strip():
        return "", f"no stock reply for {t.status}"
    if t.draft:
        return "", "a reply draft is saved on the ticket"
    if drafted:
        return "", "an agent's reply draft is waiting to be adopted"
    if t.visibility == "private" and not ctx.vault.available:
        return "", "private, and the vault key is not loaded"  # the reply would have to be sealed
    if moved is None or moved.get("to") != t.status:
        return "", "no record of the move in the log"
    if moved.get("via") == "triage":
        return "", "moved by the triage import"
    if t.status == "accepted":
        if moved.get("from") not in BEFORE_ACCEPTED:
            return "", f"moved back from {moved.get('from')}"
        return await thread.fill_for(ctx, db, tpl, t), ""
    refs = thread.patch_refs_text([p for p in await thread.patches_for(db, t) if nameable(p)])
    if not refs:
        return "", "no linked patch the desk may name as the fix"
    return await thread.fill_for(ctx, db, tpl, t, patch_refs=refs), ""


async def resting(
    ctx: Context, db: AsyncSession, *, now: datetime, since: datetime | None = None
) -> list[Resting]:
    """Every bounty ticket resting untold at `accepted` or `patched` past the grace period, oldest
    move first, each with the reply the desk would send or the reason it sends none. `since` leaves
    out moves made at or before it (the worker's start); without it the whole backlog is read."""
    q = select(Ticket).where(
        Ticket.kind == "bounty",
        Ticket.status.in_(TELLS),
        Ticket.status_changed_at <= now - GRACE,
        tsvc.UNTOLD,
    )
    if since is not None:
        q = q.where(Ticket.status_changed_at > since)
    tickets = list((await db.execute(q.order_by(Ticket.status_changed_at.asc()))).scalars().all())
    if not tickets:
        return []
    ids = [t.id for t in tickets]
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
    out: list[Resting] = []
    for t in tickets:
        text, why = await _reply_for(ctx, db, t, moves.get(t.id), t.id in drafted)
        out.append(Resting(t, t.id, t.status, t.status_changed_at, text, why))
    return out


async def tell_resting(
    ctx: Context, db: AsyncSession, *, now: datetime | None = None, backlog: bool = False
) -> list[dict]:
    """Send the stock reply on every ticket `resting` has one for, at most `BATCH` in a run. Each
    ticket is its own savepoint under the ticket's row lock, re-read before anything is sent, so a
    reply or a status move that landed a moment ago wins and one ticket the desk refuses does not stop
    the rest. Returns what was sent, `{"ticket", "status", "reply"}` each; the caller commits and then
    mails (`notify.take_owed`). The worker's run tells moves made since it first ran, and its first
    run only notes when that was; `backlog` is the run made by hand over everything resting."""
    now = now or tsvc.utcnow()
    since = None
    if not backlog:
        mark = await sync.get_cursor(db, CURSOR)
        if not mark:
            await sync.set_cursor(db, CURSOR, now.isoformat())
            return []
        since = datetime.fromisoformat(mark)
    told: list[dict] = []
    for r in await resting(ctx, db, now=now, since=since):
        if len(told) >= BATCH:
            break
        if not r.text:
            continue
        t = r.ticket
        try:
            async with db.begin_nested():
                await tsvc.lock(db, t)
                if t.status_changed_at != r.moved_at or not tsvc.untold(t) or t.draft:
                    continue  # it moved, or a person got there first, while this was being read
                reply = await thread.add_reply(ctx, db, SYSTEM, t, r.text)
                notify.owe(db, reply)
                told.append({"ticket": r.id, "status": r.status, "reply": reply.id})
        except HTTPException as e:
            log.warning("%s at %s not told: %s", r.id, r.status, e.detail)
    return told

"""The desk tells a reporter what nobody has. A bounty ticket that comes to rest at `accepted`, at
`patched` or `closed`, and stays there untold past a grace period, is sent the programme's reply for
where it rests, signed by the desk (`thread.DESK_NAME`): the `accepted` or `patched` template, or the
template named for the closing reason (`duplicate`, `invalid`, `out-of-scope`, `answered`, `stale`).
The reply goes the way every reply goes: onto the thread, out through the ticket's own channel, and by
mail once the worker has committed (`notify.owe`).

The rule lives in one sweep over state (`tell_resting`, run by the worker) rather than in `set_status`,
so it holds whatever moved the ticket (a person, an adopted proposal, a family ruling, a merged PR, the
internal tracker) and a ticket walked through `accepted` on its way to `patched` is told once, about
where it stopped. `resting` is the rule itself: every ticket it covers, with the reply it would be
sent or the reason it is left. The worker and the backlog command both send exactly what it lists.

Whose words. The frame is always the programme's. A closing reply has one slot, `{reason}`, and the
desk fills it with the agent's reply draft only when all of this holds (`reason_review`): a person
adopted the draft; the closure it rides with was the same agent's proposal, made with it, and a person
adopted that too; the ticket is private, so the words go to the reporter who filed it and nobody
else; and the text passes `thread.review_reason(closing=True)`. Otherwise the slot takes the stock
line for that closing reason (`closing_reasons` in the public copy) and the draft is dropped; its
proposal keeps the text. A duplicate has no slot: it gets the programme's duplicate reply whatever an
agent drafted, as it does when the close is adopted (`proposals.tell_duplicate`). Nobody reads a
closing reply before it goes: the check reads form, not truth. What stands behind it is the person
who adopted the closure, the fifteen minutes they have to take it back, and the reporter's way back,
which is a new report (a closed ticket takes no more messages, `reporters.reply`).

What the desk leaves to a person, and so to the outbox:
- anything a person has in hand: a reply sent since the move (`told_at`), or, on a closed ticket,
  in the quarter of an hour before it (the closing words, then the close); an agent's reply draft
  waiting to be adopted; a draft saved on a ticket that is not closed; and a draft adopted on a
  ticket well after it closed (`TOGETHER`), which went to that person's editor;
- a ticket closed from its chat thread (`/close`), where the close was said in front of whoever asked;
- a `patched` ticket with no patch the desk may name on its own (`nameable`): the words are "fixed in
  ...", and a stranger's unmerged PR that says "Fixes #N" is not where it was fixed (XE-0128);
- a move back (`fixing` to `accepted`: the fix was withdrawn), which "read and accepted" does not fit;
- a bulk triage import;
- a private ticket while the vault key is not loaded.
A withdrawal is the reporter's own word and nothing is owed back.

The worker tells only moves made since it first ran the rule for that status (`STARTS`: one cursor
for accepted and patched, one for closed), so switching either on sends nothing by itself. What was
already resting then is swept by hand, once, with the same rule: `desk tell-backlog --dry-run` to read
what would go, `desk tell-backlog` to send it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import SYSTEM
from ..context import Context
from ..db import each_committed, passed_over
from ..models import Event, PatchRef, Proposal, Ticket
from . import notify, sync, thread
from . import tickets as tsvc

log = logging.getLogger("desk.tell")

TELLS = ("accepted", "patched", "closed")  # each has a reply template: its own name, or the closing reason's
UNOWED = ("withdrawn",)  # closing reasons that are the reporter's own word
GRACE = timedelta(minutes=15)  # a person's own words come first; this is how long the desk waits for them
# When the worker first ran the sweep for each group of statuses; a move from before it is the backlog's.
STARTS = ((("accepted", "patched"), "tell:since"), (("closed",), "tell:since:closed"))
BATCH = 50  # replies in one run; the rest go on the next
BEFORE_ACCEPTED = ("new", "triaging", "needs-info")
# A draft and a closure belong together when they were proposed within this of each other, and adopted
# within it too: a draft adopted later than this after the close went to a person's editor.
TOGETHER = timedelta(minutes=10)
CHAT = ("discord", "telegram")  # sources whose thread a person closes from, in front of the asker


def together(a: Proposal, b: Proposal) -> bool:
    """Whether two proposals are one reading's: the same token, made within `TOGETHER` of each other."""
    if a.token_id != b.token_id:
        return False
    return not (a.created_at and b.created_at and abs(a.created_at - b.created_at) > TOGETHER)


STOCK = "stock"  # whose words: the programme's alone


def owed(kind: str, closed_reason: str | None) -> bool:
    """Whether a ticket of this kind closed for this reason is told by the desk: a bounty report, for
    any reason but the reporter's own. The sweep's query says the same in SQL (`resting`)."""
    return kind == "bounty" and closed_reason not in UNOWED


def nameable(pr: PatchRef) -> bool:
    """A patch the desk may name as the fix without a person reading it first: anything except a PR the
    sync linked off GitHub that GitHub does not call merged. Whoever opens a PR saying "Fixes #N" gets it
    linked; only a merge, or a person or the team's agent linking it, makes it the fix."""
    return not (pr.added_by == SYSTEM.actor and pr.state in ("open", "closed"))


def reason_review(
    ctx: Context, t: Ticket, text: str, draft: Proposal | None, closure: Proposal | None
) -> str | None:
    """Why an agent's reply draft may not go out as the reason in the desk's closing reply, or None
    when it may. `draft` is the reply-draft proposal the text came from and `closure` the status
    proposal that closes the ticket: both pending, on the triage page, which shows what adopting the
    row will send; both adopted, in the sweep. The one place the question is asked.

    A draft is a closure's reason when the agent that proposed the closure proposed the draft with it:
    the same token, and the two within `TOGETHER` of each other. An acknowledgement an earlier
    reading left on the ticket, or one a later reading adds, says "confirmed, with the team", and
    adopted beside the closure it would go out above "closed as invalid". A closure made by hand has no
    reading of an agent's behind it. And an agent's words go to the reporter who filed the report and
    to nobody else: on a public ticket the reply is read by everyone and posted to the issue under
    the team's account, so the stock line goes there whatever the draft says."""
    if t.visibility != "private":
        return "the ticket is public"
    if draft is None:
        return "no adopted draft of an agent's"
    if closure is None:
        return "the closure was not an agent's proposal"
    if draft.token_id != closure.token_id:
        return "the draft and the closure are different agents'"
    if draft.created_at and closure.created_at and abs(draft.created_at - closure.created_at) > TOGETHER:
        return "the draft was not written with the closure"
    return thread.review_reason(ctx, text, t, closing=True)


@dataclass
class Resting:
    """An untold ticket at a status the desk tells: the reply it would be sent (`text`) and whose
    words fill it (`words`: `STOCK`, or `proposal:<id>` for an agent's adopted reason, with `held`
    saying why a draft on the ticket was not used), or why the desk leaves it to a person (`why`).
    The row's own facts are copied out when it is read, so they are still there after a savepoint
    elsewhere in the sweep has rolled back, and `seen` is what the reply was decided on: read again
    under the row's lock, a ticket that no longer matches it is left for the next run."""

    ticket: Ticket
    id: str
    status: str
    name: str  # the reply template's name: the status, or the closing reason of a closed ticket
    moved_at: datetime
    text: str = ""
    why: str = ""
    words: str = ""
    held: str = ""
    seen: tuple = ()


def picked(r: Resting, only: str = "") -> bool:
    """Whether a run narrowed to `only` (a status, or a closing reason) takes this ticket."""
    return not only or only in (r.status, r.name)


def describe(r: Resting) -> str:
    """One line on what the desk does with a resting ticket, for the dry run."""
    if not r.text:
        return f"left: {r.why}"
    if r.words != STOCK:
        return f"tell, with the agent's reason ({r.words})"
    return "tell, in stock words" + (f" (draft not used: {r.held})" if r.held else "")


def _seen(t: Ticket) -> tuple:
    return (t.status, t.closed_reason, t.status_changed_at, t.draft, t.visibility, t.duplicate_of)


async def _reply_for(
    ctx: Context,
    db: AsyncSession,
    t: Ticket,
    moved: dict | None,
    drafted: bool,
    draft: Proposal | None = None,
    closure: Proposal | None = None,
) -> tuple[str, str, str, str]:
    """The programme's reply for where `t` rests, as (text, why, words, held): the text, or "" and
    why the desk has none it may send; whose words fill it; and, when a draft on the ticket was not
    used for them, why. `moved` is the payload of the ticket's latest `ticket.status` event;
    `drafted`, whether an agent's reply draft is waiting on it; `draft` and `closure`, the adopted
    proposals a closed ticket's saved draft and its closing came from, if they came from any."""
    closed = t.status == "closed"
    name = (t.closed_reason or "") if closed else t.status
    tpl = ctx.config.reply_templates.get(name, "")
    if t.status not in TELLS or not tpl.strip():
        return "", f"no stock reply for {t.status}{f' ({name})' if closed else ''}", "", ""
    if t.draft and not closed:
        return "", "a reply draft is saved on the ticket", "", ""
    if drafted:
        return "", "an agent's reply draft is waiting to be adopted", "", ""
    if t.visibility == "private" and not ctx.vault.available:
        return "", "private, and the vault key is not loaded", "", ""  # the reply would have to be sealed
    if moved is None or moved.get("to") != t.status or (closed and moved.get("closed_reason") != name):
        return "", "no record of the move in the log", "", ""
    if moved.get("via") == "triage":
        return "", "moved by the triage import", "", ""
    if closed and str(moved.get("via") or "").partition(":")[0] in CHAT:
        return "", "closed from its chat thread, where the close was said", "", ""
    if closed and t.told_at and t.told_at >= t.status_changed_at - GRACE:
        # the closing words and then the close, minutes apart: `untold` reads that as silence since
        return "", "the reporter was written to just before the close", "", ""
    if closed and t.draft and draft is not None and draft.decided_at:
        if draft.decided_at > t.status_changed_at + TOGETHER:
            # "Use as draft" on a ticket that had already closed: the person is writing the reply
            return "", "a reply draft was adopted after the close; it is in the editor", "", ""
    if closed and name == "duplicate":
        if not t.duplicate_of:
            return "", "closed as a duplicate of nothing", "", ""
        held = "a duplicate gets the programme's duplicate reply" if t.draft else ""
        return await thread.fill_for(ctx, db, tpl, t), "", STOCK, held
    if closed:
        held = (reason_review(ctx, t, t.draft, draft, closure) or "") if t.draft else ""
        if t.draft and not held:
            text = await thread.fill_for(ctx, db, tpl, t, reason=t.draft.strip())
            return text, "", f"proposal:{draft.id}", ""
        reason = ctx.config.closing_reasons.get(name, "").strip()
        if not reason:
            return "", f"no stock reason for {name}", "", ""
        return await thread.fill_for(ctx, db, tpl, t, reason=reason), "", STOCK, held
    if t.status == "accepted":
        if moved.get("from") not in BEFORE_ACCEPTED:
            return "", f"moved back from {moved.get('from')}", "", ""
        return await thread.fill_for(ctx, db, tpl, t), "", STOCK, ""
    refs = thread.patch_refs_text([p for p in await thread.patches_for(db, t) if nameable(p)])
    if not refs:
        return "", "no linked patch the desk may name as the fix", "", ""
    return await thread.fill_for(ctx, db, tpl, t, patch_refs=refs), "", STOCK, ""


def _closure_id(moved: dict | None) -> int | None:
    """The proposal whose adoption made the move, from the move's `via` (`proposal:<id>`)."""
    kind, _, pid = str((moved or {}).get("via") or "").partition(":")
    return int(pid) if kind == "proposal" and pid.isdigit() else None


async def resting(
    ctx: Context, db: AsyncSession, *, now: datetime, since: dict[str, datetime] | None = None
) -> list[Resting]:
    """Every bounty ticket resting untold at `accepted`, `patched` or `closed` past the grace period,
    oldest move first, each with the reply the desk would send or the reason it sends none. `since`
    gives, by status, the time at or before which a move is left out (the worker's start for that
    status); without it the whole backlog is read."""
    q = select(Ticket).where(
        Ticket.kind == "bounty",
        Ticket.status.in_(TELLS),
        Ticket.status_changed_at <= now - GRACE,
        tsvc.UNTOLD,
        or_(Ticket.closed_reason.is_(None), Ticket.closed_reason.notin_(UNOWED)),
    )
    if since is not None:
        q = q.where(
            or_(*[and_(Ticket.status == s, Ticket.status_changed_at > at) for s, at in since.items()])
        )
    tickets = list((await db.execute(q.order_by(Ticket.status_changed_at.asc()))).scalars().all())
    if not tickets:
        return []
    ids = [t.id for t in tickets]
    is_draft = and_(Proposal.ticket_id.in_(ids), Proposal.field == "reply_draft")
    waiting = select(Proposal.ticket_id).where(is_draft, Proposal.state == "pending")
    drafted = set((await db.execute(waiting)).scalars())
    ev = select(Event.ref, Event.payload).where(Event.kind == "ticket.status", Event.ref.in_(ids))
    moves = {ref: payload for ref, payload in (await db.execute(ev.order_by(Event.index.asc()))).all()}
    # what a closed ticket's saved draft and its closing came from: the reply draft adopted last on
    # it (that adoption is the only writer of `Ticket.draft`), and the proposal the close names
    adopted: dict[str, Proposal] = {}
    latest = select(Proposal).where(is_draft, Proposal.state == "adopted")
    for pr in (await db.execute(latest.order_by(Proposal.decided_at.asc(), Proposal.id.asc()))).scalars():
        adopted[pr.ticket_id] = pr  # ascending, so the last one adopted is the one kept
    closers = {t.id: _closure_id(moves.get(t.id)) for t in tickets if t.status == "closed" and t.draft}
    wanted = [pid for pid in closers.values() if pid is not None]
    closures: dict[int, Proposal] = {}
    if wanted:
        got = select(Proposal).where(
            Proposal.id.in_(wanted), Proposal.field == "status", Proposal.state == "adopted"
        )
        closures = {pr.id: pr for pr in (await db.execute(got)).scalars().all()}
    out: list[Resting] = []
    for t in tickets:
        closure = closures.get(closers.get(t.id) or 0)
        if closure is not None and closure.ticket_id != t.id:
            closure = None
        text, why, words, held = await _reply_for(
            ctx, db, t, moves.get(t.id), t.id in drafted, adopted.get(t.id), closure
        )
        name = (t.closed_reason or "") if t.status == "closed" else t.status
        out.append(Resting(t, t.id, t.status, name, t.status_changed_at, text, why, words, held, _seen(t)))
    return out


async def _since(db: AsyncSession, now: datetime) -> dict[str, datetime]:
    """By status, when the worker began telling it. A group met for the first time starts now: this
    run and every later one tell its moves made after this moment, and nothing from before."""
    since: dict[str, datetime] = {}
    for statuses, key in STARTS:
        mark = await sync.get_cursor(db, key)
        if not mark:
            mark = now.isoformat()
            await sync.set_cursor(db, key, mark)
        for s in statuses:
            since[s] = datetime.fromisoformat(mark)
    return since


async def tell_resting(
    ctx: Context,
    db: AsyncSession,
    *,
    now: datetime | None = None,
    backlog: bool = False,
    only: str = "",
    limit: int = BATCH,
) -> list[dict]:
    """Send the programme's reply on every ticket `resting` has one for, at most `BATCH` in a run. Each
    ticket is its own savepoint under the ticket's row lock, re-read before anything is sent, so a
    reply, a status move or a newly adopted draft that landed a moment ago wins and one ticket the
    desk refuses does not stop the rest; and each is committed before the next (`each_committed`).
    Returns what was sent, `{"ticket", "status", "reply", "words"}` each; the caller commits what it
    writes itself and then mails (`notify.take_owed`). The worker's run tells
    moves made since it first ran for that status, and its first run only notes when that was;
    `backlog` is the run made by hand over everything resting, which may be narrowed to one status
    or closing reason (`only`) and stopped short (`limit`, never more than `BATCH`)."""
    now = now or tsvc.utcnow()
    since = None if backlog else await _since(db, now)
    told: list[dict] = []
    async for r in each_committed(db, await resting(ctx, db, now=now, since=since)):
        if len(told) >= min(limit, BATCH):
            break
        if not r.text or not picked(r, only):
            continue
        t = r.ticket
        try:
            async with db.begin_nested():
                await tsvc.lock(db, t)
                if _seen(t) != r.seen or not tsvc.untold(t):
                    continue  # it moved, or a person got there first, while this was being read
                reply = await thread.add_reply(ctx, db, SYSTEM, t, r.text, via=f"tell:{r.words}")
                notify.owe(db, reply)
                told.append({"ticket": r.id, "status": r.status, "reply": reply.id, "words": r.words})
        except HTTPException as e:
            log.warning("%s at %s not told: %s", r.id, r.status, e.detail)
        except Exception as e:
            passed_over(f"telling {r.id} at {r.status}", e)
    return told

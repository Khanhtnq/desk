"""Proposals: an agent's suggested change to a ticket fact, pending until a human adopts or rejects it.

Adopting writes the field through the same code path a human edit uses (so vocabulary and permission
checks apply) and records who adopted what, proposed by which token. A `reply_draft` proposal is
never written to the ticket's facts: adopting it hands the text to the reply editor, or, from the
triage page, sends it when the desk reads it as a plain acknowledgement (`send_review`).

A duplicate is told. Adopting a close-as-duplicate, by any path (one chip, a row, the shown rows, a
family), sends the programme's duplicate reply under the person ruling (`tell_duplicate`); an agent's
reply draft on that ticket is folded into it, never sent, never left in the editor.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import Principal, can, can_see, require, require_field
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
    if field == "status":
        # checked here, not only on adoption: a proposal the desk could never apply would otherwise sit
        # on the ticket until a person clicked it and met the 400 the agent should have (XE-1054)
        if not isinstance(value, (str, dict)):
            raise HTTPException(400, "status proposals are a string or {status, closed_reason}")
        status = value if isinstance(value, str) else value.get("status")
        closed_reason = None if isinstance(value, str) else value.get("closed_reason")
        if status not in tsvc.STATUSES:
            raise HTTPException(400, f"unknown status {status!r}; one of {list(tsvc.STATUSES)}")
        if status not in tsvc.TRANSITIONS[t.kind] and status != t.status:
            # `accepted` on a support question: a status of the other door, which no path reaches
            raise HTTPException(400, f"a {t.kind} ticket has no status {status}")
        reasons = sorted(tsvc.CLOSED_REASONS_FOR[t.kind])
        if status == "closed" and closed_reason not in reasons:
            raise HTTPException(400, f"closing a {t.kind} ticket needs closed_reason from {reasons}")
        if status != "closed" and closed_reason:
            raise HTTPException(400, "closed_reason goes with status closed only")
    if field in tsvc.FACT_VOCAB:
        # a fact: checked as set_facts will check it and kept as set_facts would store it. The value is
        # a key before anyone adopts it (the family of a canonical is the pending duplicate_of proposals
        # equal to its id), so `xe-0142` filed its ticket under a family of its own; and a value no
        # ticket could hold waited for a person to click into the 400 (XE-1054)
        value = await tsvc.fact_value(ctx, db, t, field, value)
        if field == "assessed_tier" and t.status in ("awarded", "paid") and value != t.assessed_tier:
            raise HTTPException(409, f"the ticket is {t.status}; the tier behind the award stands")
        if field == "visibility" and value == "public" and t.visibility == "private":
            raise HTTPException(400, "use disclose to make a private ticket public")
    if field == "reply_draft" and not isinstance(value, str):
        raise HTTPException(400, "a reply draft is a string")
    if field == "award_xe":
        if t.kind != "bounty":
            raise HTTPException(400, "a support question carries no award")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HTTPException(400, "award_xe is a whole number of XE, 0 or more")
        if value > tsvc.AWARD_MAX // 1_000_000:
            # with no tier yet there is no ceiling to check against, and `set_award` refuses this
            # whatever the tier: it waited for a person to adopt it, summed into the proposed totals
            raise HTTPException(400, f"award_xe is at most {tsvc.AWARD_MAX // 1_000_000:,} XE")
        ceiling = ctx.config.ceiling_micro(t.assessed_tier) // 1_000_000
        if ceiling and value > ceiling * 2:
            raise HTTPException(400, f"award_xe exceeds twice the {t.assessed_tier} ceiling ({ceiling} XE)")
        if not reason or len(reason.strip()) < 20:
            raise HTTPException(400, "an award proposal needs a reason of at least 20 characters")
        micro = value * 1_000_000
        if t.award_approved_at and micro != t.award_xe:
            raise HTTPException(
                409, "the award is approved; take approval back before changing the amount"
            )
        if t.status in ("awarded", "paid") and micro != t.award_xe:
            raise HTTPException(409, f"the ticket is {t.status}; the award stands")
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


async def fill_awards(ctx: Context, db: AsyncSession, p: Principal, ids: list[str], step: str) -> dict:
    """Give every listed ticket that has no amount one, from the awards page in one click. Where an agent
    has proposed an amount the newest pending proposal is adopted through `decide`, so the log shows the
    adoption and the agent's reason; where none has, the amount is the named step of the tier's ceiling
    from `award_steps` in config, the same figure the agents are told to propose. Nothing is approved.
    Each ticket is its own savepoint: one the desk refuses is reported under `skipped` and left as it
    was. A ticket that already has an amount is left alone; this fills blanks, it does not revise."""
    if step not in ctx.config.award_steps:
        raise HTTPException(400, f"step must be one of {list(ctx.config.award_steps)}")
    filled: list[dict] = []
    skipped: list[dict] = []
    # as stored, before anything is matched against them: `xe-0042` found its ticket (`get`) and
    # missed its pending proposal, so the step's figure was set over the agent's and nothing was adopted
    ids = [tsvc.ticket_id(i) for i in ids]
    pending = await pending_field_for(db, ids, "award_xe")
    # ids read up front: a savepoint rollback later in the loop may expire a row (XE-0862)
    newest = {tid: (prs[0], prs[0].id) for tid, prs in pending.items() if prs}
    for tid in ids:
        t = await tsvc.get(db, tid)
        if t is None or not can_see(p, t):
            skipped.append({"ticket": tid, "why": "no such ticket"})
            continue
        await tsvc.lock(db, t)  # "has no amount" as the row is now, not as this request read it
        if t.award_xe is not None:
            skipped.append({"ticket": tid, "why": "already has an amount"})
            continue
        try:
            async with db.begin_nested():
                if tid in newest:
                    pr, pid = newest[tid]
                    out = await decide(ctx, db, p, pr, True)
                    filled.append({"ticket": tid, "award_xe": out["award_xe"], "from": f"proposal #{pid}"})
                    continue
                require(p, "award", t)
                if not ctx.config.ceiling_micro(t.assessed_tier):
                    raise HTTPException(
                        409, "an award needs an assessed tier first; set the tier, then the amount"
                    )
                xe = ctx.config.award_xe(t.assessed_tier, step, t.area)
                if not xe:
                    raise HTTPException(
                        409, f"the {step} step of {t.assessed_tier} rounds to nothing; set it by hand"
                    )
                await tsvc.set_award(ctx, db, p, t, xe * 1_000_000, step=step)
                filled.append({"ticket": tid, "award_xe": xe * 1_000_000, "from": f"{step} step"})
        except HTTPException as e:
            skipped.append({"ticket": tid, "why": str(e.detail)})
    return {"filled": filled, "skipped": skipped}


async def pending_for(db: AsyncSession, t: Ticket) -> list[Proposal]:
    q = select(Proposal).where(Proposal.ticket_id == t.id).order_by(Proposal.created_at.desc())
    return list((await db.execute(q)).scalars().all())


async def get(db: AsyncSession, pid: int) -> Proposal | None:
    return (await db.execute(select(Proposal).where(Proposal.id == pid))).scalar_one_or_none()


def _closes(pr: Proposal) -> bool:
    if pr.field == "duplicate_of":
        return True
    if pr.field != "status":
        return False
    v = pr.value.get("value")
    return (v.get("status") if isinstance(v, dict) else v) == "closed"


FOLDED = "the programme's duplicate reply goes instead"


def send_review(ctx: Context, prs: list[Proposal], pr: Proposal, t: Ticket) -> str | None:
    """Why this reply draft should wait in the editor rather than go out on adoption, or None when the
    desk may send it as it stands. The text rule is `thread.review_reason`; on top of it, a draft that
    rides with a closure or a duplicate ruling, a draft on a closed ticket, and a draft proposed before
    the reporter was last written to all wait: the person may have said something since. A draft riding
    with a close-as-duplicate is `FOLDED`: adopting that close sends the programme's reply, not this."""
    from . import thread

    if t.status == "closed":
        return "the ticket is closed"
    others = [o for o in prs if o.state == "pending" and o.id != pr.id]
    if any(_is_dup_close(o) for o in others):
        return FOLDED
    if any(_closes(o) for o in others):
        return "goes with a closure"
    if t.told_at and pr.created_at and t.told_at > pr.created_at:
        return "the reporter has been written to since"
    return thread.review_reason(ctx, thread.fill(ctx, str(pr.value.get("value")), t), t)


def _is_dup_close(pr: Proposal) -> bool:
    v = pr.value.get("value")
    return (
        pr.field == "status"
        and isinstance(v, dict)
        and (v.get("status"), v.get("closed_reason")) == ("closed", "duplicate")
    )


def _require_proposal_permission(p: Principal, pr: Proposal, t: Ticket, *, adopt: bool) -> None:
    if not can_see(p, t):
        raise HTTPException(404, "no such ticket")
    if pr.field == "award_xe":
        require(p, "award", t)
    elif pr.field == "reply_draft":
        require(p, "reply", t)
    else:
        require_field(p, pr.field)
        if adopt and pr.field == "status" and _is_dup_close(pr):
            require(p, "reply", t)


async def decide(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    pr: Proposal,
    adopt: bool,
    *,
    reason: str = "",
    send_plain: bool = False,
) -> dict:
    """Adopt or reject. Returns what happened, including a reply draft when that is what was adopted.
    With `send_plain`, a reply draft the desk reads as a plain acknowledgement (see `send_review`) is
    sent to the reporter under the adopter's name instead of waiting in the editor; `sent` carries the
    reply id and `reply_text` the words, for the caller to mail. Any other draft still waits, and
    `review` says why."""
    if p.user is None or not can(p, "adopt"):
        raise HTTPException(403, "adopting is a reviewer's action")
    await db.flush()
    await db.refresh(pr, with_for_update=True)  # two clicks in the same second decide it once (XE-0814)
    if pr.state != "pending":
        raise HTTPException(409, f"proposal is already {pr.state}")
    t = await tsvc.get(db, pr.ticket_id)
    if t is None:
        raise HTTPException(404, "ticket is gone")
    _require_proposal_permission(p, pr, t, adopt=adopt)
    out: dict[str, Any] = {"proposal": pr.id, "ticket": t.id, "field": pr.field, "adopted": adopt}
    value = pr.value.get("value")
    if adopt:
        if pr.field == "reply_draft":
            from . import thread

            text = await thread.fill_for(ctx, db, str(value), t)
            why = send_review(ctx, await pending_for(db, t), pr, t) if send_plain else None
            if send_plain and why is None:
                r = await thread.add_reply(ctx, db, p, t, text)  # clears t.draft
                out["sent"] = r.id
                out["reply_text"] = text
            else:
                # filled and kept on the ticket until a reply is sent; the editor is not the only copy
                t.draft = out["reply_draft"] = text
                if send_plain:
                    out["review"] = why
        elif pr.field == "status":
            status = value if isinstance(value, str) else value.get("status")
            reason_c = None if isinstance(value, str) else value.get("closed_reason")
            dup = _is_dup_close(pr)
            # an agent may propose a status several hops away; the desk walks the allowed path, one
            # logged hop at a time, inside this transaction
            out["path"] = await tsvc.set_status_via_path(
                ctx, db, p, t, status, closed_reason=reason_c, reason=reason, via=f"proposal:{pr.id}"
            )
            out["status"] = t.status
            if dup:
                why = reason or f"duplicate of {t.duplicate_of}"
                out.update(await tell_duplicate(ctx, db, p, t, reason=why))
        elif pr.field == "award_xe":
            # sets the amount only; approval stays a separate, deliberate click
            if t.status in ("awarded", "paid") and int(value) * 1_000_000 != t.award_xe:
                raise HTTPException(409, f"the ticket is {t.status}; the award stands")
            await tsvc.set_award(ctx, db, p, t, int(value) * 1_000_000)
            out["award_xe"] = int(value) * 1_000_000
        else:
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


async def tell_duplicate(ctx: Context, db: AsyncSession, p: Principal, t: Ticket, *, reason: str) -> dict:
    """The reporter of a ticket just closed as a duplicate is told, with the programme's duplicate reply
    under the person ruling. Any pending reply draft on the ticket is recorded adopted and folded into
    it: a duplicate gets one reply, the programme's, whatever an agent drafted. Returns `sent` (the
    reply id), `reply_text` (for the caller to mail) and `folded` (the draft proposal ids)."""
    from . import thread

    require(p, "reply", t)
    folded: list[int] = []
    for d in await pending_for(db, t):
        if d.state == "pending" and d.field == "reply_draft":
            await decide(ctx, db, p, d, True, reason=reason)  # sets t.draft; the reply below clears it
            folded.append(d.id)
    text = await thread.render_template(ctx, db, "duplicate", t)
    r = await thread.add_reply(ctx, db, p, t, text)
    return {"sent": r.id, "reply_text": text, "folded": folded}


async def pending_duplicates_of(db: AsyncSession, tid: str) -> list[tuple[Ticket, Proposal | None]]:
    """The family waiting for one ruling: open tickets carrying a pending `duplicate_of` proposal that
    names `tid`, and open tickets already marked `duplicate_of` `tid` whose close is still pending (the
    mark was adopted on its own; the proposal in the pair is then None)."""
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
    )
    out: dict[str, tuple[Ticket, Proposal | None]] = {t.id: (t, pr) for t, pr in (await db.execute(q)).all()}
    marked = (
        select(Ticket)
        .join(Proposal, Proposal.ticket_id == Ticket.id)
        .where(
            Ticket.duplicate_of == tid,
            Ticket.status != "closed",
            Ticket.id != tid,
            Proposal.state == "pending",
            Proposal.field == "status",
        )
        .distinct()
    )
    for t in (await db.execute(marked)).scalars().all():
        if t.id in out:
            continue
        if any(_is_dup_close(o) for o in await pending_for(db, t) if o.state == "pending"):
            out[t.id] = (t, None)
    return [out[k] for k in sorted(out)]


async def close_duplicates(
    ctx: Context, db: AsyncSession, p: Principal, canon: Ticket, only: list[str] | None = None
) -> dict:
    """Rule a whole family at once. For every open ticket with a pending `duplicate_of` proposal naming
    `canon` (or already marked so, with the close still pending): adopt the mark, set the verdict, close
    as duplicate (walking the status path), and tell the reporter (`tell_duplicate`). Each ticket is its
    own savepoint, so one the desk refuses (a transition, a permission) is reported and left as it was
    while the rest go through. The decision stays a person's: one click for a family instead of four per
    ticket."""
    if p.user is None or not can(p, "adopt"):
        raise HTTPException(403, "adopting is a reviewer's action")
    require_field(p, "duplicate_of")
    require_field(p, "status")
    closed: list[dict] = []
    skipped: list[dict] = []
    # ids read before any savepoint: a rollback expires the row and a lazy load of it is a 500
    family = [(t, pr, t.id) for t, pr in await pending_duplicates_of(db, canon.id)]
    if only is not None:
        # a subset is named by ids as stored; one that is not in the family is said so, not passed
        # over (`xe-0002` closed nothing and the answer listed nothing). An empty subset is none of
        # the family, not all of it
        only = [tsvc.ticket_id(i) for i in only]
        members = {tid for _, _, tid in family}
        outside = f"not a pending duplicate of {canon.id}"
        skipped += [{"ticket": i, "why": outside} for i in only if i not in members]
    for t, pr, tid in family:
        if only is not None and tid not in only:
            continue
        try:
            async with db.begin_nested():
                require(p, "reply", t)
                why = f"duplicate of {canon.id}"
                via = f"family:{canon.id}"
                if pr is not None:
                    await decide(ctx, db, p, pr, True, reason=why)
                others = {o.field: o for o in await pending_for(db, t) if o.state == "pending"}
                v = others.get("verdict")
                if v is not None and v.value.get("value") == "duplicate":
                    await decide(ctx, db, p, v, True, reason=why)
                elif t.verdict != "duplicate":
                    await tsvc.set_facts(ctx, db, p, t, {"verdict": "duplicate"}, reason=why, via=via)
                s = others.get("status")
                if s is not None and _is_dup_close(s):
                    told = await decide(ctx, db, p, s, True, reason=why)  # closes and tells
                else:
                    await tsvc.set_status_via_path(
                        ctx, db, p, t, "closed", closed_reason="duplicate", reason=why, via=via
                    )
                    told = await tell_duplicate(ctx, db, p, t, reason=why)
                closed.append(
                    {"ticket": tid, "status": t.status, "reply": told["sent"], "text": told["reply_text"]}
                )
        except HTTPException as e:
            skipped.append({"ticket": tid, "why": str(e.detail)})
    return {"canonical": canon.id, "closed": closed, "skipped": skipped}


async def decide_many(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    adopt: list[int],
    reject: list[int],
    *,
    send_plain: bool = False,
) -> dict:
    """Many decisions in one request, each its own savepoint: one the desk refuses (a transition the
    state machine will not make, a field the role may not set) is reported in `skipped` and the rest go
    through. A batch that stopped at the first refusal left a reviewer adopting one by one (XE-0872).
    Adoptions run marks first, then status changes, then reply drafts, whatever order the ids came in: a
    close-as-duplicate needs the mark already on the ticket, and a draft needs to see the closure adopted
    beside it (`send_review`). A draft folded into a duplicate reply is reported under `decided` with
    `folded`, not under `skipped`."""
    if p.user is None or not can(p, "adopt"):
        raise HTTPException(403, "adopting is a reviewer's action")
    decided: list[dict] = []
    skipped: list[dict] = []
    found = {pr.id: pr for pr in [await get(db, i) for i in adopt] if pr is not None}
    rank = {"status": 1, "reply_draft": 2}

    def order(x: tuple[int, bool]) -> int:
        pr = found.get(x[0]) if x[1] else None
        return rank.get(pr.field, 0) if pr is not None else 0

    todo: list[tuple[int, bool]] = sorted([(i, True) for i in adopt], key=order)
    todo += [(i, False) for i in reject]
    folded: dict[int, str] = {}
    for pid, yes in todo:
        if pid in folded:
            decided.append({"proposal": pid, "ticket": folded[pid], "field": "reply_draft", "adopted": True,
                            "folded": True})
            continue
        pr = await get(db, pid)
        if pr is None or pr.state != "pending":
            skipped.append({"proposal": pid, "why": "not pending" if pr else "no such proposal"})
            continue
        tid, field = pr.ticket_id, pr.field  # read before the savepoint (see close_duplicates)
        try:
            async with db.begin_nested():
                out = await decide(ctx, db, p, pr, yes, send_plain=send_plain)
        except HTTPException as e:
            skipped.append({"proposal": pid, "ticket": tid, "field": field, "why": str(e.detail)})
            continue
        decided.append(out)
        for fid in out.get("folded", []):
            folded[fid] = tid
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
    if "duplicate_of" in fields or any(_is_dup_close(pr) for pr in prs):
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
        if pr.field == "assessed_tier" and pr.value.get("value"):
            return str(pr.value["value"])  # a proposal to clear it holds null: not the tier "None"
    return t.assessed_tier


class TriageRow:
    __slots__ = ("ticket", "proposals", "views", "tier", "note", "canonical", "mine", "klass", "reply")

    def __init__(self, t: Ticket, prs: list[Proposal]):
        self.ticket = t
        self.proposals = prs
        self.views: set[str] = set()
        self.tier: str | None = None
        self.note: Note | None = None
        self.canonical: Ticket | None = None
        self.mine: list[int] = []  # the proposal ids the viewer's roles let them adopt; set by the page
        self.klass: list[Ticket] = []  # the other reports on the same engineering ticket
        self.reply: str | None = None  # "sends" | "review" | None: what adopting does with its reply draft

    @property
    def duplicate_of(self) -> str | None:
        """The canonical the row groups under: the pending proposal, else the mark already on the ticket."""
        for pr in self.proposals:
            if pr.field == "duplicate_of" and pr.value.get("value"):
                # a proposal to clear the mark holds null: not a family headed "None"
                return str(pr.value["value"])
        return self.ticket.duplicate_of


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

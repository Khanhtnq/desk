"""Tickets: ids, creation, the severity-ordered list, facts, the status machine, serialisation.

Every change is an event in the log with the ticket id as `ref`. Events on private tickets are
non-public. Nothing here sends anything anywhere; mirroring is the worker's job.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import Principal, can, can_see
from ..config import Config
from ..context import Context
from ..models import (
    AREAS,
    CLOSED_REASONS,
    EFFORTS,
    GATES,
    KINDS,
    SOURCES,
    STATUSES,
    TIERS,
    TOPICS,
    VERDICTS,
    VISIBILITIES,
    IdCounter,
    PatchRef,
    Proposal,
    Reporter,
    Ticket,
    User,
)
from ..vault import VaultError

ID_PREFIX = {"bounty": "XE", "support": "XS"}

TRANSITIONS: dict[str, dict[str, set[str]]] = {
    "bounty": {
        "new": {"triaging", "closed"},
        "triaging": {"needs-info", "accepted", "closed"},
        "needs-info": {"triaging", "accepted", "closed"},
        "accepted": {"fixing", "patched", "triaging", "closed"},
        "fixing": {"patched", "accepted", "closed"},
        "patched": {"disclosed", "awarded", "fixing"},
        "disclosed": {"awarded"},
        "awarded": {"paid"},
        "paid": set(),
        "closed": {"triaging"},
    },
    "support": {
        "new": {"triaging", "closed"},
        "triaging": {"needs-info", "closed"},
        "needs-info": {"triaging", "closed"},
        "closed": {"triaging"},
    },
}
CLOSED_REASONS_FOR = {"bounty": set(CLOSED_REASONS), "support": {"answered", "stale", "duplicate"}}
FACT_VOCAB: dict[str, tuple[str, ...] | None] = {
    "area": AREAS,
    "claimed_tier": TIERS,
    "assessed_tier": TIERS,
    "verdict": VERDICTS,
    "mainnet_gate": GATES,
    "effort_eng": EFFORTS,
    "visibility": VISIBILITIES,
    "duplicate_of": None,
    "internal_ref": None,
    "assignee_id": None,
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---- ids --------------------------------------------------------------------------------------------


def format_id(kind: str, n: int) -> str:
    return f"{ID_PREFIX[kind]}-{n:04d}"


async def next_id(db: AsyncSession, kind: str) -> str:
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    row = (
        await db.execute(select(IdCounter).where(IdCounter.kind == kind).with_for_update())
    ).scalar_one_or_none()
    if row is None:
        row = IdCounter(kind=kind, next=1)
        db.add(row)
        await db.flush()
        row = (
            await db.execute(select(IdCounter).where(IdCounter.kind == kind).with_for_update())
        ).scalar_one()
    n = row.next
    row.next = n + 1
    await db.flush()
    return format_id(kind, n)


# ---- bodies (the vault) -----------------------------------------------------------------------------


def set_body(ctx: Context, t: Ticket, text: str) -> None:
    if t.visibility == "private":
        if not ctx.vault.available:
            raise HTTPException(503, "private reports cannot be stored: the vault key is not loaded")
        t.body_sealed = ctx.vault.seal_text(text)
        t.body = ""
    else:
        t.body = text
        t.body_sealed = None


def body_for(ctx: Context, t: Ticket) -> str:
    """The body for a reader the authorisation layer has already admitted. Callers log the read."""
    if t.visibility == "private":
        if not t.body_sealed:
            return ""
        try:
            return ctx.vault.open_text(t.body_sealed)
        except VaultError:
            return "[sealed; the vault key is not loaded]"
    return t.body


# ---- creation ---------------------------------------------------------------------------------------


@dataclass
class NewTicket:
    kind: str
    title: str
    body: str = ""
    visibility: str = "public"
    source: str = "web"
    source_repo: str = ""
    source_ref: str = ""
    source_url: str = ""
    reporter_id: int | None = None
    area: str | None = None
    claimed_tier: str | None = None
    source_created_at: datetime | None = None
    github_state: str = ""


async def create(
    ctx: Context, db: AsyncSession, actor: str, spec: NewTicket, *, status: str = "new"
) -> Ticket:
    if spec.kind not in KINDS or spec.visibility not in VISIBILITIES or spec.source not in SOURCES:
        raise HTTPException(400, "bad kind, visibility or source")
    tid = await next_id(db, spec.kind)
    t = Ticket(
        id=tid,
        kind=spec.kind,
        visibility=spec.visibility,
        source=spec.source,
        source_repo=spec.source_repo,
        source_ref=spec.source_ref,
        source_url=spec.source_url,
        reporter_id=spec.reporter_id,
        title=spec.title[:512],
        area=spec.area,
        claimed_tier=spec.claimed_tier,
        status=status,
        source_created_at=spec.source_created_at,
        github_state=spec.github_state,
    )
    set_body(ctx, t, spec.body)
    db.add(t)
    await db.flush()
    await ctx.events.append(
        db,
        "ticket.created",
        actor,
        {
            "ticket": tid,
            "kind": t.kind,
            "visibility": t.visibility,
            "source": t.source,
            "source_ref": f"{t.source_repo}#{t.source_ref}" if t.source_repo else t.source_ref,
            "title": t.title if t.visibility == "public" else "",
            "status": t.status,
        },
        ref=tid,
        public=t.visibility == "public",
    )
    return t


async def find_by_source(db: AsyncSession, source: str, repo: str, ref: str) -> Ticket | None:
    q = select(Ticket).where(
        Ticket.source == source, Ticket.source_repo == repo, Ticket.source_ref == str(ref)
    )
    return (await db.execute(q)).scalar_one_or_none()


async def get(db: AsyncSession, tid: str) -> Ticket | None:
    return (await db.execute(select(Ticket).where(Ticket.id == tid.upper()))).scalar_one_or_none()


async def get_for(db: AsyncSession, p: Principal, tid: str) -> Ticket:
    t = await get(db, tid)
    if t is None or not can_see(p, t):
        raise HTTPException(404, "no such ticket")
    return t


# ---- the list ---------------------------------------------------------------------------------------


def _rank(cfg: Config, column):
    order = cfg.tier_order
    return case({tier: i for i, tier in enumerate(order)}, value=column, else_=len(order))


# While a bug is confirmed and unfixed, the team's assessment of it (tier, verdict, gate, effort, which
# internal ticket carries it) is a ranked list of what works against XE and when it will stop working.
# The ticket, its status and its thread stay public; the assessment is published from `patched` on. The
# gate and the effort are planning data and stay with the team at every stage.
ASSESSMENT_HELD = ("new", "triaging", "needs-info", "accepted", "fixing")


def assessment_held(t: Ticket) -> bool:
    return t.kind == "bounty" and t.status in ASSESSMENT_HELD


def sees_assessment(p: Principal) -> bool:
    """The team, its agents and the desk itself see the assessment at every stage."""
    return p.is_team or p.is_agent or p.kind == "system"


def shown_tier(t: Ticket, p: Principal) -> str | None:
    """The tier a reader is shown: the assessment, or the reporter's claim while the assessment is held."""
    if t.assessed_tier and (sees_assessment(p) or not assessment_held(t)):
        return t.assessed_tier
    return t.claimed_tier


def _shown_tier_col():
    return case((Ticket.status.in_(ASSESSMENT_HELD), Ticket.claimed_tier), else_=Ticket.assessed_tier)


@dataclass
class Filters:
    kind: str | None = "bounty"
    status: str | None = "open"  # open | closed | <status> | all
    area: str | None = None
    verdict: str | None = None
    gate: str | None = None
    source: str | None = None
    tier: str | None = None
    has_pr: bool | None = None
    has_internal: bool | None = None
    pending: bool | None = None  # has pending proposals
    q: str | None = None
    sort: str = "severity"  # severity | age | updated
    offset: int = 0
    limit: int = 100


async def list_tickets(db: AsyncSession, cfg: Config, p: Principal, f: Filters) -> list[Ticket]:
    q = select(Ticket)
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    if f.kind and f.kind != "all":
        q = q.where(Ticket.kind == f.kind)
    if f.status == "open":
        q = q.where(Ticket.status.notin_(("closed", "paid")))
    elif f.status == "closed":
        q = q.where(Ticket.status.in_(("closed", "paid")))
    elif f.status and f.status != "all":
        q = q.where(Ticket.status == f.status)
    if f.area:
        q = q.where(Ticket.area == f.area)
    # A filter is a question about the facts, so the public gets the facts it is shown and no more: a
    # held ticket matches on the reporter's claim, never on the assessment, and the team-only axes
    # (gate, internal ref, pending proposals) are not questions it can ask.
    full = sees_assessment(p)
    unheld = Ticket.status.notin_(ASSESSMENT_HELD)
    if f.verdict:
        q = q.where(Ticket.verdict == f.verdict if full else (Ticket.verdict == f.verdict) & unheld)
    if f.gate and full:
        q = q.where(Ticket.mainnet_gate == f.gate)
    if f.source:
        q = q.where(Ticket.source == f.source)
    if f.tier:
        q = q.where(Ticket.assessed_tier == f.tier if full else _shown_tier_col() == f.tier)
    if f.has_pr is not None:
        sub = select(PatchRef.ticket_id).where(PatchRef.ticket_id == Ticket.id).exists()
        q = q.where(sub if f.has_pr else ~sub)
    if f.has_internal is not None and full:
        q = q.where(Ticket.internal_ref != "" if f.has_internal else Ticket.internal_ref == "")
    if f.pending is not None and full:
        sub = select(Proposal.id).where(Proposal.ticket_id == Ticket.id, Proposal.state == "pending").exists()
        q = q.where(sub if f.pending else ~sub)
    if f.q:
        like = f"%{f.q.strip()}%"
        issue = Ticket.source_ref == f.q.strip().lstrip("#")
        match = Ticket.title.ilike(like) | Ticket.id.ilike(like) | issue
        if full:
            match = match | (Ticket.internal_ref.ilike(like))
        q = q.where(match)
    if f.sort == "age":
        q = q.order_by(func.coalesce(Ticket.source_created_at, Ticket.created_at).asc())
    elif f.sort == "updated":
        q = q.order_by(Ticket.updated_at.desc())
    else:
        q = q.order_by(
            _rank(cfg, Ticket.assessed_tier if full else _shown_tier_col()),
            _rank(cfg, Ticket.claimed_tier),
            func.coalesce(Ticket.source_created_at, Ticket.created_at).asc(),
        )
    q = q.offset(max(f.offset, 0)).limit(min(max(f.limit, 1), 500))
    return list((await db.execute(q)).scalars().all())


async def counts(db: AsyncSession, p: Principal, kind: str = "bounty") -> dict[str, int]:
    q = select(Ticket.status, func.count()).where(Ticket.kind == kind).group_by(Ticket.status)
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    rows = (await db.execute(q)).all()
    out = {s: 0 for s in STATUSES}
    for s, n in rows:
        out[s] = int(n)
    out["open"] = sum(v for k, v in out.items() if k not in ("closed", "paid"))
    out["total"] = sum(v for k, v in out.items() if k in STATUSES)
    return out


async def pending_counts(db: AsyncSession, ticket_ids: list[str]) -> dict[str, int]:
    if not ticket_ids:
        return {}
    q = (
        select(Proposal.ticket_id, func.count())
        .where(Proposal.ticket_id.in_(ticket_ids), Proposal.state == "pending")
        .group_by(Proposal.ticket_id)
    )
    return {tid: int(n) for tid, n in (await db.execute(q)).all()}


async def patch_counts(db: AsyncSession, ticket_ids: list[str]) -> dict[str, int]:
    if not ticket_ids:
        return {}
    q = (
        select(PatchRef.ticket_id, func.count())
        .where(PatchRef.ticket_id.in_(ticket_ids))
        .group_by(PatchRef.ticket_id)
    )
    return {tid: int(n) for tid, n in (await db.execute(q)).all()}


async def release_view(db: AsyncSession, cfg: Config, p: Principal) -> dict[str, list[Ticket]]:
    """Every `before` and `decide` ticket grouped by area, severity order within each."""
    rows = await list_tickets(db, cfg, p, Filters(kind="bounty", status="all", limit=500))
    out: dict[str, list[Ticket]] = {a: [] for a in cfg.areas}
    for t in rows:
        if t.mainnet_gate in ("before", "decide"):
            out.setdefault(t.area or "other", []).append(t)
    return {a: ts for a, ts in out.items() if ts}


AWARD_DUE_STATUSES = ("accepted", "fixing", "patched", "disclosed")


async def awards_due(db: AsyncSession, cfg: Config, p: Principal) -> list[Ticket]:
    """Bounty tickets that are valid and moving toward payment but have no award, or one not yet approved."""
    q = select(Ticket).where(
        Ticket.kind == "bounty",
        Ticket.status.in_(AWARD_DUE_STATUSES + ("awarded",)),
        (Ticket.award_xe.is_(None)) | (Ticket.award_approved_at.is_(None)),
    )
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    q = q.order_by(_rank(cfg, Ticket.assessed_tier), Ticket.id.asc())
    return list((await db.execute(q)).scalars().all())


async def awards_approved_unawarded(db: AsyncSession, cfg: Config, p: Principal) -> list[Ticket]:
    """Bounty tickets whose award is approved but whose status has not caught up: approval is the
    treasurer's decision, `awarded` is the ticket saying so in public (and the leaderboard). A private
    ticket has to be disclosed first, which is why this list exists."""
    q = select(Ticket).where(
        Ticket.kind == "bounty",
        Ticket.award_approved_at.isnot(None),
        Ticket.status.notin_(("awarded", "paid")),
    )
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    q = q.order_by(Ticket.award_approved_at.asc())
    return list((await db.execute(q)).scalars().all())


def award_next_step(t: Ticket) -> tuple[str, str | None]:
    """What has to happen for an approved award to become `awarded`: (text, status to set now or None)."""
    if t.status in ("awarded", "paid"):
        return "done", None
    if t.status == "disclosed" or (t.status == "patched" and t.visibility == "public"):
        step = "set the status to awarded; this publishes it and lists the reporter on the leaderboard"
        return step, "awarded"
    if t.status == "patched":
        return "disclose the report first (it is private), then set awarded", None
    if t.status == "closed":
        return "closed with an approved award: reopen it, or take the approval back", None
    return "the fix has not landed; awarded follows patched (or disclosed)", None


async def outbox(db: AsyncSession, cfg: Config, p: Principal, kind: str = "bounty") -> list[Ticket]:
    """Tickets whose status moved past triage but whose thread has not been told since. A reply sets
    told_at; set_status sets status_changed_at. For the bounty that is fixed-but-silent; for support it is
    a question moved to needs-info or closed without anyone having written to the asker. A withdrawal is
    the reporter's own word, so nothing is owed back and it is left out."""
    q = select(Ticket).where(
        Ticket.kind == kind, Ticket.status.notin_(("new", "triaging")), Ticket.status_changed_at.isnot(None)
    )
    q = q.where((Ticket.closed_reason.is_(None)) | (Ticket.closed_reason != "withdrawn"))
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    q = q.where((Ticket.told_at.is_(None)) | (Ticket.told_at < Ticket.status_changed_at))
    q = q.order_by(_rank(cfg, Ticket.assessed_tier), Ticket.status_changed_at.asc())
    return list((await db.execute(q)).scalars().all())


async def leaderboard(db: AsyncSession) -> list[dict]:
    q = (
        select(
            Reporter.id, Reporter.github_login, Reporter.display_name, func.sum(Ticket.award_xe), func.count()
        )
        .join(Ticket, Ticket.reporter_id == Reporter.id)
        .where(
            Ticket.status.in_(("awarded", "paid")),
            Ticket.award_approved_at.isnot(None),
            Ticket.visibility == "public",  # a private award is the team's business until disclosure
        )
        .group_by(Reporter.id)
        .order_by(func.sum(Ticket.award_xe).desc())
    )
    return [
        {"reporter_id": rid, "login": login, "name": name, "award_xe": int(total or 0), "tickets": int(n)}
        for rid, login, name, total, n in (await db.execute(q)).all()
    ]


# ---- facts ------------------------------------------------------------------------------------------


async def set_facts(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    t: Ticket,
    changes: dict[str, Any],
    *,
    reason: str = "",
    via: str = "",
) -> dict[str, Any]:
    """Set fact fields. The caller has checked permissions per field (authz.require_field). Returns the
    applied diff. Vocabulary is enforced here so a bad value never lands however it arrived."""
    diff: dict[str, Any] = {}
    for k, v in changes.items():
        if k not in FACT_VOCAB:
            raise HTTPException(400, f"{k} is not a fact field")
        vocab = FACT_VOCAB[k]
        if k == "area":
            vocab = TOPICS if t.kind == "support" else AREAS
        if v in ("", None):
            v = "" if k == "internal_ref" else None
        elif vocab is not None and v not in vocab:
            raise HTTPException(400, f"{k} must be one of {list(vocab)}")
        if k == "duplicate_of" and v:
            v = str(v).upper()
            if v == t.id:
                raise HTTPException(400, "a ticket cannot duplicate itself")
            if await get(db, v) is None:
                raise HTTPException(400, f"{v} does not exist")
        if k == "assignee_id" and v is not None:
            u = (await db.execute(select(User).where(User.id == int(v)))).scalar_one_or_none()
            if u is None:
                raise HTTPException(400, "no such user")
            v = int(v)
        if k == "visibility" and v == "public" and t.visibility == "private":
            raise HTTPException(400, "use disclose to make a private ticket public")
        old = getattr(t, k)
        if old == v:
            continue
        if k == "visibility" and v == "private":
            text = t.body
            t.visibility = "private"
            set_body(ctx, t, text)
            await seal_thread(ctx, db, t)
        else:
            setattr(t, k, v)
        diff[k] = {"from": old, "to": v}
    if diff:
        await ctx.events.append(
            db,
            "ticket.facts",
            p.actor,
            {
                "ticket": t.id,
                "changes": diff,
                "reason": reason[:500],
                "via": via,
            },
            ref=t.id,
            public=t.visibility == "public",
        )
    return diff


# ---- status -----------------------------------------------------------------------------------------


async def set_status(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    t: Ticket,
    status: str,
    *,
    closed_reason: str | None = None,
    reason: str = "",
    force: bool = False,
    via: str = "",
) -> None:
    if status not in STATUSES:
        raise HTTPException(400, f"unknown status {status!r}")
    allowed = TRANSITIONS[t.kind].get(t.status, set())
    if not force and status != t.status and status not in allowed:
        raise HTTPException(409, f"{t.kind} ticket cannot go from {t.status} to {status}")
    if status == "closed":
        if closed_reason not in CLOSED_REASONS_FOR[t.kind]:
            raise HTTPException(400, f"closing needs a reason from {sorted(CLOSED_REASONS_FOR[t.kind])}")
        if closed_reason == "duplicate" and not t.duplicate_of:
            raise HTTPException(400, "closing as duplicate needs duplicate_of")
    if status == "disclosed":
        if t.visibility != "private":
            raise HTTPException(400, "only a private ticket is disclosed; a public one goes to awarded")
        n = int(
            (
                await db.execute(select(func.count()).select_from(PatchRef).where(PatchRef.ticket_id == t.id))
            ).scalar_one()
        )
        if n == 0 and not force:
            raise HTTPException(400, "disclosure needs a linked patch")
    if status == "awarded" and not force:
        if t.award_xe is None or t.award_approved_at is None:
            raise HTTPException(400, "awarded needs an approved award")
    if status == "paid" and not t.paid_ref and not force:
        raise HTTPException(400, "paid needs paid_ref")
    old, old_reason = t.status, t.closed_reason
    if old == status and old_reason == closed_reason:
        return
    t.status = status
    t.closed_reason = closed_reason if status == "closed" else None
    t.status_changed_at = utcnow()
    if status == "disclosed" and t.disclosed_at is None:
        t.disclosed_at = utcnow()
    if status == "disclosed" and t.visibility == "private":
        # the one disclosure path, whoever called: the body leaves the vault and the ticket goes public
        # here, so a proposal, a walked path or a force can never leave a sealed ticket at "disclosed"
        text = body_for(ctx, t)
        t.visibility = "public"
        t.body, t.body_sealed = text, None
        await ctx.events.append(
            db, "ticket.disclosed", p.actor, {"ticket": t.id, "title": t.title}, ref=t.id, public=True
        )
    await ctx.events.append(
        db,
        "ticket.status",
        p.actor,
        {
            "ticket": t.id,
            "from": old,
            "to": status,
            "closed_reason": t.closed_reason,
            "was": old_reason,
            "reason": reason[:500],
            "via": via,
        },
        ref=t.id,
        public=t.visibility == "public",
    )


# Statuses a walked path may end on but never pass through: each is a decision in its own right.
TERMINAL = frozenset({"closed", "awarded", "paid"})


def status_path(kind: str, current: str, target: str) -> list[str] | None:
    """The shortest run of allowed transitions from `current` to `target`, excluding `current` itself;
    `[]` when already there, None when unreachable. Only forward edges of TRANSITIONS are walked, the
    terminal statuses are never intermediates, and the path never re-enters `current`."""
    if current == target:
        return []
    table = TRANSITIONS.get(kind, {})
    seen = {current}
    frontier: list[list[str]] = [[current]]
    while frontier:
        nxt: list[list[str]] = []
        for path in frontier:
            for s in sorted(table.get(path[-1], set())):
                if s == target:
                    return path[1:] + [s]
                if s in seen or s in TERMINAL:
                    continue
                seen.add(s)
                nxt.append(path + [s])
        frontier = nxt
    return None


async def set_status_via_path(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    t: Ticket,
    status: str,
    *,
    closed_reason: str | None = None,
    reason: str = "",
    via: str = "",
) -> list[str]:
    """set_status, hop by hop, when the target is more than one move away. Every hop is a real status
    change with the same `via` and reason, so each is logged and hooked exactly as a click would be;
    only the last hop carries `closed_reason`. Returns the hops taken. No path at all is the usual 409,
    raised before anything moves."""
    if status not in STATUSES:
        raise HTTPException(400, f"unknown status {status!r}")
    path = status_path(t.kind, t.status, status)
    if path is None:
        raise HTTPException(409, f"{t.kind} ticket cannot go from {t.status} to {status}")
    if not path:
        await set_status(ctx, db, p, t, status, closed_reason=closed_reason, reason=reason, via=via)
        return []
    for hop in path:
        last = hop == path[-1]
        await set_status(
            ctx, db, p, t, hop, closed_reason=closed_reason if last else None, reason=reason, via=via
        )
    return path


async def seal_thread(ctx: Context, db: AsyncSession, t: Ticket) -> dict:
    """A ticket just went private: everything that arrived while it was public follows the body into the
    vault (thread messages, attachment blobs), and any reply still queued for a public mirror is pulled
    back. Returns counts. Replies keep their plain row, as they do on tickets born private."""
    if not ctx.vault.available:
        raise HTTPException(503, "the vault key is not loaded; the ticket cannot be made private")
    from pathlib import Path

    from ..models import Attachment, Message, Reply

    n_msg = n_att = n_rep = 0
    for m in (await db.execute(select(Message).where(Message.ticket_id == t.id))).scalars().all():
        if m.body_sealed is None and m.body:
            m.body_sealed, m.body = ctx.vault.seal_text(m.body), ""
            n_msg += 1
    for a in (await db.execute(select(Attachment).where(Attachment.ticket_id == t.id))).scalars().all():
        if not a.sealed:
            path = Path(ctx.settings.blob_dir) / a.blob_path
            if path.exists():
                path.write_bytes(ctx.vault.seal(path.read_bytes()))
            a.sealed = True
            n_att += 1
    q = select(Reply).where(Reply.ticket_id == t.id, Reply.mirror == "queued")
    for r in (await db.execute(q)).scalars().all():
        r.mirror = "none"
        n_rep += 1
    return {"messages": n_msg, "attachments": n_att, "replies_unqueued": n_rep}


async def disclose(ctx: Context, db: AsyncSession, p: Principal, t: Ticket) -> None:
    """Private → public. The work is in set_status (status `disclosed` unseals and flips visibility, and
    logs `ticket.disclosed`); the worker then opens the GitHub issue. Kept as the named entry point."""
    await set_status(ctx, db, p, t, "disclosed")


# An amount may be set from `accepted` on (the awards pass does that); approval waits for the fix.
AWARD_APPROVABLE_STATUSES = ("patched", "disclosed", "awarded", "paid")


def award_approvable(t: Ticket) -> str | None:
    """None when the award may be approved now; otherwise the reason it may not, for the button and the 409."""
    if t.award_xe is None:
        return "nothing to approve"
    if t.status not in AWARD_APPROVABLE_STATUSES:
        return f"approval waits for the fix: the ticket is {t.status}, not patched or disclosed"
    return None


async def set_award(
    ctx: Context, db: AsyncSession, p: Principal, t: Ticket, award_xe: int | None, *, approve: bool | None = None
) -> None:
    """Set the amount, approve it, or take approval back. `approve` None leaves approval as it is; True
    needs a set amount on a patched or disclosed ticket; False clears it (the amount stays)."""
    cfg = ctx.config
    if award_xe is not None:
        if award_xe < 0:
            raise HTTPException(400, "award must be ≥ 0")
        if t.award_approved_at and award_xe != t.award_xe:
            raise HTTPException(409, "the award is approved; take approval back before changing the amount")
        ceiling = cfg.ceiling_micro(t.assessed_tier)
        if ceiling and award_xe > ceiling * 2:
            raise HTTPException(
                400, f"award exceeds twice the {t.assessed_tier} ceiling; exceptional awards need a note"
            )
        t.award_xe = award_xe
    if approve is True:
        why = award_approvable(t)
        if why:
            raise HTTPException(409 if t.award_xe is not None else 400, why)
        t.award_approved_by = p.user.id if p.user else None
        t.award_approved_at = utcnow()
    elif approve is False:
        if t.status in ("awarded", "paid"):
            raise HTTPException(409, f"the ticket is {t.status}; the award stands")
        t.award_approved_by = None
        t.award_approved_at = None
    await ctx.events.append(
        db,
        "ticket.award",
        p.actor,
        {
            "ticket": t.id,
            "award_xe": t.award_xe,
            "approved": bool(t.award_approved_at),
            "tier": t.assessed_tier,
        },
        ref=t.id,
        public=t.visibility == "public",
    )


# ---- serialisation ----------------------------------------------------------------------------------


def ticket_url(ctx: Context, t: Ticket) -> str:
    """One canonical URL per ticket: the bare id at the root of its front door, e.g. https://bounty.xe.network/XE-0032."""
    base = f"{ctx.settings.scheme}://{ctx.settings.hosts['bounty' if t.kind == 'bounty' else 'support']}"
    return f"{base}/{t.id}"


def to_dict(ctx: Context, t: Ticket, p: Principal, *, with_body: bool = False) -> dict:
    cfg = ctx.config
    full = sees_assessment(p)
    shown = full or not assessment_held(t)
    d: dict[str, Any] = {
        "id": t.id,
        "kind": t.kind,
        "visibility": t.visibility,
        "source": t.source,
        "source_repo": t.source_repo,
        "source_ref": t.source_ref,
        "source_url": t.source_url,
        "reporter_id": t.reporter_id,
        "title": t.title,
        "area": t.area,
        "claimed_tier": t.claimed_tier,
        "assessed_tier": t.assessed_tier if shown else None,
        "verdict": t.verdict if shown else None,
        "duplicate_of": t.duplicate_of,
        "tracked": bool(t.internal_ref),
        "internal_ref": t.internal_ref if shown else "",
        "internal_url": ctx.settings.internal_url(t.internal_ref) if shown else None,
        "status": t.status,
        "closed_reason": t.closed_reason,
        "github_state": t.github_state,
        "disclosed_at": _iso(t.disclosed_at),
        "award_xe": t.award_xe,
        "award_approved": bool(t.award_approved_at),
        "paid_ref": t.paid_ref,
        "created_at": _iso(t.created_at),
        "updated_at": _iso(t.updated_at),
        "source_created_at": _iso(t.source_created_at),
        "told_at": _iso(t.told_at),
        "status_changed_at": _iso(t.status_changed_at),
        "url": ticket_url(ctx, t),
    }
    if full:
        d["mainnet_gate"] = t.mainnet_gate
        d["effort_eng"] = t.effort_eng
        d["effort_agent"] = cfg.effort_agent(t.effort_eng) if t.effort_eng else None
        d["assignee_id"] = t.assignee_id
    if can(p, "read:payout_address"):
        d["payout_address"] = t.payout_address
    if with_body:
        d["body"] = body_for(ctx, t)
    return d


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None

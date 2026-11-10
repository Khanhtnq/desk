"""Tickets: ids, creation, the severity-ordered list, facts, the status machine, serialisation.

Every change is an event in the log with the ticket id as `ref`. Events on private tickets are
non-public. Nothing here sends anything anywhere; mirroring is the worker's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import case, func, literal, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import Principal, can, can_see, require, require_field
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

# Three answers to "where is it": still being worked (open), fixed and somewhere between the merge and the
# money (fixed), or closed without a fix. The headline counts and the list filters use the same split.
OPEN_STATUSES = ("new", "triaging", "needs-info", "accepted", "fixing")
FIXED_STATUSES = ("patched", "disclosed", "awarded", "paid")

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


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(s: str | None, *, one_line: bool = False) -> str:
    """Reporter or team text on its way to a text column: NUL and the other control characters go
    (Postgres refuses NUL and the request would end as a bare 500, XE-1426), lone surrogates go, and a
    one-line field loses its line breaks too."""
    s = (s or "").replace("\x00", "")
    s = _CONTROL.sub("", s)
    s = s.encode("utf-8", "ignore").decode("utf-8", "ignore")
    if one_line:
        s = " ".join(s.split())
    return s


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def xe_amount(micro: int) -> str:
    """Micro-XE as a reader sees it: 5,000, or 0.05 and never 0.5 for a twentieth (XE-0493)."""
    whole, frac = divmod(int(micro), 1_000_000)
    return f"{whole:,}" if frac == 0 else f"{whole:,}.{frac:06d}".rstrip("0")


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


PRIVATE_TIERS = ("critical", "severe")


def claimed(tier: str | None) -> str | None:
    """A claimed tier as it is stored: one of TIERS, or None when none was given. Case and the space
    around it are the sender's and are dropped; anything else is refused. A tier the desk did not
    recognise used to be stored as no claim, and the report it came with was filed public (XE-1932,
    XE-2123)."""
    t = (tier or "").strip().lower()
    if not t:
        return None
    if t not in TIERS:
        raise HTTPException(400, f"claimed_tier must be one of {list(TIERS)}")
    return t


def born_private(spec: NewTicket, tier: str | None) -> bool:
    """A bounty report claiming Critical or Severe is private from its first write, whoever writes it:
    the reporter's form, the team's API, an import (XE-1932, XE-2166). Asked by `create`, which every
    writer goes through, so no route has to remember it. The one exception is the ticket made for a
    GitHub issue: the issue is public where it was filed, and the desk's copy follows it until a person
    seals it. `source: github` with no issue behind it (typed in by the team) is not that."""
    if spec.visibility == "private":
        return True
    on_github = spec.source == "github" and bool(spec.source_repo and spec.source_ref)
    return spec.kind == "bounty" and tier in PRIVATE_TIERS and not on_github


async def set_kind(
    ctx: Context, db: AsyncSession, actor: str, t: Ticket, kind: str, *, via: str = ""
) -> None:
    """Move a ticket to the other door; the id and the history stay. What does not carry over is
    cleared here, for both callers (the team's route and `/bounty` in a chat thread):
    the area, since areas are engineering areas on the bounty and topics on support, and the claimed
    tier, since a claim is made by a reporter filing on the bounty and a ticket that arrives there by
    conversion has made none. So no conversion produces a public report claiming Critical or Severe
    (the XE-1932 sweep); a person who then sets the claim also decides the visibility."""
    if kind not in KINDS:
        raise HTTPException(400, f"kind is one of {list(KINDS)}")
    old = t.kind
    t.kind, t.area, t.claimed_tier = kind, None, None
    payload = {"ticket": t.id, "from": old, "to": kind, **({"via": via} if via else {})}
    await ctx.events.append(db, "ticket.kind", actor, payload, ref=t.id, public=t.visibility == "public")


async def create(ctx: Context, db: AsyncSession, actor: str, spec: NewTicket) -> Ticket:
    """A new ticket, at `new`. It took a status once, which no caller passed: a second writer of a
    status that asked none of `set_status`'s questions (a private ticket born awarded)."""
    if spec.kind not in KINDS or spec.visibility not in VISIBILITIES or spec.source not in SOURCES:
        raise HTTPException(400, "bad kind, visibility or source")
    tier = claimed(spec.claimed_tier)
    if spec.kind != "bounty":
        tier = None  # a question claims nothing, so a later conversion has no claim to inherit
    visibility = "private" if born_private(spec, tier) else "public"
    if visibility == "private" and not ctx.vault.available:
        raise HTTPException(503, "private reports cannot be taken right now: the vault key is not loaded")
    tid = await next_id(db, spec.kind)
    t = Ticket(
        id=tid,
        kind=spec.kind,
        visibility=visibility,
        source=spec.source,
        source_repo=spec.source_repo,
        source_ref=spec.source_ref,
        source_url=spec.source_url,
        reporter_id=spec.reporter_id,
        title=clean_text(spec.title, one_line=True)[:512],
        area=(spec.area or None) and spec.area[:32],
        claimed_tier=tier,
        status="new",
        source_created_at=spec.source_created_at,
        github_state=spec.github_state,
    )
    set_body(ctx, t, clean_text(spec.body))
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
#
# A report its reporter withdraws is closed, and nothing was fixed by that: withdrawn from `accepted`
# or `fixing` it is still a confirmed, unfixed bug, so a ticket closed as withdrawn keeps its
# assessment held (the XE-1960 sweep). The rule is spelled twice, for a row and as SQL for the
# filters, and nowhere else.
ASSESSMENT_HELD = ("new", "triaging", "needs-info", "accepted", "fixing")


def assessment_held(t: Ticket) -> bool:
    if t.kind != "bounty":
        return False
    return t.status in ASSESSMENT_HELD or (t.status == "closed" and t.closed_reason == "withdrawn")


def _held():
    """`assessment_held` as a column expression; never NULL, so it can be negated."""
    withdrawn = (Ticket.status == "closed") & (func.coalesce(Ticket.closed_reason, "") == "withdrawn")
    return (Ticket.kind == "bounty") & (Ticket.status.in_(ASSESSMENT_HELD) | withdrawn)


def sees_assessment(p: Principal) -> bool:
    """The team, the desk itself, and agent tokens that take part in the working layer (XE-1560): a token
    with a write scope but no notes access sees what the public sees."""
    if p.is_team or p.kind == "system":
        return True
    return p.is_agent and can(p, "read:notes")


def shown_tier(t: Ticket, p: Principal) -> str | None:
    """The tier a reader is shown: the assessment, or the reporter's claim while the assessment is held."""
    if t.assessed_tier and (sees_assessment(p) or not assessment_held(t)):
        return t.assessed_tier
    return t.claimed_tier


def _shown_tier_col():
    return case((_held(), Ticket.claimed_tier), else_=Ticket.assessed_tier)


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
    reporter: int | None = None  # team and agents: everything one reporter has filed
    queued: bool | None = None  # past the reporter's daily cap when filed
    sort: str = "severity"  # severity | age | updated
    offset: int = 0
    limit: int = 100


def _filtered(cfg: Config, p: Principal, f: Filters):
    """The rows a filter selects, before ordering and paging; shared by the list and its total."""
    q = select(Ticket)
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    if f.kind and f.kind != "all":
        q = q.where(Ticket.kind == f.kind)
    if f.status == "open":
        q = q.where(Ticket.status.in_(OPEN_STATUSES))
    elif f.status == "fixed":
        q = q.where(Ticket.status.in_(FIXED_STATUSES))
    elif f.status == "closed":
        q = q.where(Ticket.status == "closed")
    elif f.status and f.status != "all":
        q = q.where(Ticket.status == f.status)
    if f.area:
        q = q.where(Ticket.area == f.area)
    # A filter is a question about the facts, so the public gets the facts it is shown and no more: a
    # held ticket matches on the reporter's claim, never on the assessment, and the team-only axes
    # (gate, internal ref, pending proposals) are not questions it can ask.
    full = sees_assessment(p)
    if not full and (
        f.gate or f.has_internal is not None or f.pending is not None or f.reporter is not None
        or f.queued is not None
    ):
        # the team-only axes are not questions a public caller can ask; refused, not quietly dropped
        # (XE-1560)
        raise HTTPException(403, "gate, has_internal, pending, reporter and queued are team filters")
    unheld = ~_held()
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
        # the body too: two reports of one bug rarely share a title. A private body is sealed and is
        # not searchable; the title still is.
        match = Ticket.title.ilike(like) | Ticket.id.ilike(like) | Ticket.body.ilike(like) | issue
        if full:
            match = match | (Ticket.internal_ref.ilike(like))
        q = q.where(match)
    if f.reporter is not None and full:
        q = q.where(Ticket.reporter_id == f.reporter)
    if f.queued is not None and full:
        q = q.where(Ticket.queued.is_(f.queued))
    return q


async def count_tickets(db: AsyncSession, cfg: Config, p: Principal, f: Filters) -> int:
    """How many rows the filter selects in all, so a reader paging through knows when it has them all."""
    q = select(func.count()).select_from(_filtered(cfg, p, f).subquery())
    return int((await db.execute(q)).scalar_one())


def _ordered(cfg: Config, p: Principal, f: Filters):
    """The list's query in the list's order. The id is the last key of every order: tickets tied on
    the rest (one import, one second on GitHub) had no order between them, and Postgres promises
    nothing about which of them a page boundary falls between, so a pager could be given one twice
    and the other never (XE-2271)."""
    q = _filtered(cfg, p, f)
    full = sees_assessment(p)
    # queued reports (past their reporter's daily cap) come after everything else in every order but
    # "updated"; a scanner's fortieth probe never sits above another account's first report
    age = func.coalesce(Ticket.source_created_at, Ticket.created_at).asc()
    if f.sort == "age":
        return q.order_by(Ticket.queued.asc(), age, Ticket.id.asc())
    if f.sort == "updated":
        return q.order_by(Ticket.updated_at.desc(), Ticket.id.asc())
    return q.order_by(
        Ticket.queued.asc(),
        _rank(cfg, Ticket.assessed_tier if full else _shown_tier_col()),
        _rank(cfg, Ticket.claimed_tier),
        age,
        Ticket.id.asc(),
    )


async def list_tickets(db: AsyncSession, cfg: Config, p: Principal, f: Filters) -> list[Ticket]:
    q = _ordered(cfg, p, f).offset(max(f.offset, 0)).limit(min(max(f.limit, 1), 500))
    return list((await db.execute(q)).scalars().all())


async def every_ticket(db: AsyncSession, cfg: Config, p: Principal, f: Filters) -> list[Ticket]:
    """Every ticket the filters match and the reader may see, in the list's order, read in one
    statement. Pages are each their own snapshot: a ticket filed or moved between two of them shifts
    the rest, and a reader of every page gets one ticket twice or misses one (XE-2271). For whatever
    says "every": the export, not a page of the list."""
    return list((await db.execute(_ordered(cfg, p, f))).scalars().all())


# ---- similar tickets ----------------------------------------------------------------------------
#
# A report is never read on its own. Before a verdict, the reader is shown what else on the desk looks
# like it: tickets whose title and body share the same words (Postgres full-text, ranked), tickets that
# cite the same source paths, the same reporter's other reports, and anything already linked as a
# duplicate either way. This is the floor of the duplicate check, not the ceiling; the brief says so.

_STOP = frozenset(
    "a an and are as at be by for from has have if in into is it its no not of on or that the this to "
    "via was when where which while with without xe bug issue report vulnerability attack attacker can "
    "could allows allow any all also may might should would will does doesnt dont".split()
)
_EXT = "rs|go|py|ts|tsx|js|sol|c|cc|h|hpp|toml|yaml|yml|json|proto"
_PATH = re.compile(r"(?<![\w/.])((?:[\w.-]+/)+[\w.-]+\.(?:" + _EXT + r"))\b")


def _terms(*texts: str, limit: int = 24) -> list[str]:
    seen: list[str] = []
    for text_ in texts:
        for w in re.findall(r"[a-z][a-z0-9_]{2,}", (text_ or "").lower()):
            if w not in _STOP and w not in seen:
                seen.append(w)
            if len(seen) >= limit:
                return seen
    return seen


def cited_paths(body: str, limit: int = 6) -> list[str]:
    out: list[str] = []
    for m in _PATH.finditer(body or ""):
        path = m.group(1).strip("./")
        if path and path not in out:
            out.append(path)
        if len(out) >= limit:
            break
    return out


@dataclass
class Similar:
    ticket: Ticket
    score: float
    why: list[str]


async def similar(
    db: AsyncSession, cfg: Config, p: Principal, t: Ticket, body: str = "", limit: int = 10
) -> list[Similar]:
    """Tickets the reader should look at before ruling on `t`, best match first. `body` is the report's
    body as the admitted reader may see it (sealed bodies are opened by the caller, or left empty)."""
    base = select(Ticket).where(Ticket.id != t.id, Ticket.kind == t.kind)
    if not can(p, "read:private"):
        base = base.where(Ticket.visibility == "public")
    found: dict[str, Similar] = {}

    def hit(row: Ticket, score: float, why: str) -> None:
        s = found.setdefault(row.id, Similar(row, 0.0, []))
        s.score += score
        if why not in s.why:
            s.why.append(why)

    # words: the title weighs most, the first part of the body fills in the nouns the title left out
    terms = _terms(t.title, " ".join((body or "")[:2000].split()))
    if terms:
        tsq = func.to_tsquery("english", " | ".join(terms))
        doc = func.to_tsvector("english", Ticket.title + literal(" ") + Ticket.body)
        rank = func.ts_rank_cd(doc, tsq)
        rows = (
            await db.execute(base.add_columns(rank).where(doc.op("@@")(tsq)).order_by(rank.desc()).limit(30))
        ).all()
        if rows:
            top = max(float(r[1]) for r in rows) or 1.0
            for row, r in rows:
                hit(row, 0.6 * float(r) / top, "same words")
    # paths: a report that names the same file is about the same code, whatever it calls the bug
    paths = cited_paths(body)
    if paths:
        pq = base.where(or_(*[Ticket.body.ilike(f"%{path}%") for path in paths])).limit(30)
        for row in (await db.execute(pq)).scalars().all():
            shared = [path for path in paths if path in (row.body or "")]
            hit(row, 0.25 + 0.1 * (len(shared) - 1), "cites " + ", ".join(shared[:3]))
    # the reporter's other reports: a run of thin ones, or the earlier filing of this one
    if t.reporter_id:
        rq = base.where(Ticket.reporter_id == t.reporter_id).order_by(Ticket.created_at.asc()).limit(30)
        for row in (await db.execute(rq)).scalars().all():
            hit(row, 0.1, "same reporter")
    # already linked, either way round
    links = base.where(or_(Ticket.id == (t.duplicate_of or ""), Ticket.duplicate_of == t.id))
    for row in (await db.execute(links)).scalars().all():
        hit(row, 1.0, "linked as duplicate")
    for s in found.values():
        if s.ticket.area and s.ticket.area == t.area and len(s.why) > 0 and s.why != ["same reporter"]:
            s.score += 0.05
            s.why.append("same area")
    out = sorted(found.values(), key=lambda s: (-s.score, s.ticket.created_at))
    return out[:limit]


async def same_class(db: AsyncSession, p: Principal, refs: set[str]) -> dict[str, list[Ticket]]:
    """The reports behind each engineering ticket: every visible ticket carrying one of `refs` as its
    `internal_ref`, grouped by ref, oldest first. One engineering ticket is one class of bug (the fix
    brief); seeing its other reports beside a ticket is how a reviewer tells a resolution from a patch."""
    refs = {r for r in refs if r}
    if not refs:
        return {}
    q = select(Ticket).where(Ticket.internal_ref.in_(refs)).order_by(Ticket.id)
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    out: dict[str, list[Ticket]] = {r: [] for r in refs}
    for row in (await db.execute(q)).scalars().all():
        out[row.internal_ref].append(row)
    return out


async def hidden_targets(db: AsyncSession, p: Principal, tickets: list[Ticket]) -> frozenset[str]:
    """The `duplicate_of` targets among these tickets that this reader may not be told exist: private
    tickets the reader cannot open (XE-0799). One query for a whole list; every serializer and page that
    names a duplicate target consults it, so no list can name what the ticket page would not."""
    if can(p, "read:private"):
        return frozenset()
    refs = {t.duplicate_of for t in tickets if t.duplicate_of}
    if not refs:
        return frozenset()
    q = select(Ticket.id).where(Ticket.id.in_(refs), Ticket.visibility == "private")
    if p.reporter_id:
        q = q.where(Ticket.reporter_id != p.reporter_id)  # a reporter may know their own
    return frozenset((await db.execute(q)).scalars().all())


def similar_dict(
    ctx: Context, s: Similar, p: Principal, t: Ticket, hidden: frozenset[str] = frozenset()
) -> dict:
    """A row of the similar list: enough to decide whether to open it, under the usual holding rules."""
    o = s.ticket
    d = {
        "id": o.id,
        "title": o.title,
        "status": o.status,
        "closed_reason": o.closed_reason,
        "area": o.area,
        "claimed_tier": o.claimed_tier,
        "duplicate_of": o.duplicate_of if o.duplicate_of not in hidden else None,
        "created_at": _iso(o.created_at),
        "same_reporter": bool(t.reporter_id and o.reporter_id == t.reporter_id),
        "score": round(s.score, 3),
        "why": s.why,
        "url": ticket_url(ctx, o),
    }
    if sees_assessment(p) or not assessment_held(o):
        d.update(assessed_tier=o.assessed_tier, verdict=o.verdict, internal_ref=o.internal_ref)
    return d


async def counts(db: AsyncSession, p: Principal, kind: str = "bounty") -> dict[str, int]:
    q = select(Ticket.status, func.count()).where(Ticket.kind == kind).group_by(Ticket.status)
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    rows = (await db.execute(q)).all()
    out = {s: 0 for s in STATUSES}
    for s, n in rows:
        out[s] = int(n)
    out["open"] = sum(out[s] for s in OPEN_STATUSES)
    # all-time: a ticket that reached `patched` stays counted there as it moves on to the award and the
    # payment, so the three numbers read "fixed", "awarded", "closed without a fix" and never shrink
    out["fixed"] = sum(out[s] for s in FIXED_STATUSES)
    out["awarded_all"] = out["awarded"] + out["paid"]
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
    """Every `before` and `decide` ticket grouped by area, severity order within each. Every one:
    read through `every_ticket`, not the first page of the list, which past 500 bounty tickets left
    out whichever of them sorted after it."""
    rows = await every_ticket(db, cfg, p, Filters(kind="bounty", status="all"))
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


async def awards_ready(db: AsyncSession, cfg: Config, p: Principal) -> list[Ticket]:
    """Patched or disclosed bounty tickets with an amount set: everything between them and `awarded` is
    the desk's own three steps (approve, disclose a private one, mark awarded), which `settle` walks."""
    q = select(Ticket).where(
        Ticket.kind == "bounty",
        Ticket.status.in_(("patched", "disclosed")),
        Ticket.award_xe.isnot(None),
    )
    if not can(p, "read:private"):
        q = q.where(Ticket.visibility == "public")
    q = q.order_by(_rank(cfg, Ticket.assessed_tier), Ticket.id.asc())
    return list((await db.execute(q)).scalars().all())


def settle_steps(t: Ticket) -> list[str]:
    """What `settle` would do to this ticket now, in order; empty when it is awarded already."""
    steps: list[str] = []
    if t.status in ("awarded", "paid"):
        return steps
    if not t.award_approved_at:
        steps.append("approve")
    if t.visibility == "private":
        steps.append("disclose")
    steps.append("awarded")
    return steps


async def settle(ctx: Context, db: AsyncSession, p: Principal, t: Ticket) -> list[str]:
    """Walk a patched report to `awarded` in one go: approve the award if it is not, disclose a private
    one, set `awarded`. Each step is the same function the ticket page's button calls, with its checks
    (amount set, tier ceiling, vault key loaded, linked patch, allowed transition) and its log entry
    under the person clicking; the first step the desk refuses raises and the caller's savepoint
    leaves the ticket as it was. Returns the steps taken."""
    steps = settle_steps(t)
    if not steps:
        raise HTTPException(409, f"the ticket is {t.status}; nothing to settle")
    if "approve" in steps:
        require(p, "award", t)
    require_field(p, "status")
    for step in steps:
        if step == "approve":
            await set_award(ctx, db, p, t, None, approve=True)
        elif step == "disclose":
            await disclose(ctx, db, p, t)
        else:
            await set_status(ctx, db, p, t, "awarded", reason="settled from the awards page", via="settle")
    return steps


async def settle_many(ctx: Context, db: AsyncSession, p: Principal, ids: list[str]) -> dict:
    """`settle` across tickets, each its own savepoint: one the desk refuses is reported under `skipped`
    with the reason and left as it was; the rest go through."""
    settled: list[dict] = []
    skipped: list[dict] = []
    for tid in ids:
        t = await get(db, tid)
        if t is None or not can_see(p, t):
            skipped.append({"ticket": tid, "why": "no such ticket"})
            continue
        try:
            async with db.begin_nested():
                settled.append({"ticket": tid, "steps": await settle(ctx, db, p, t)})
        except HTTPException as e:
            skipped.append({"ticket": tid, "why": str(e.detail)})
    return {"settled": settled, "skipped": skipped}


def award_next_step(t: Ticket) -> tuple[str, str | None]:
    """What has to happen for an approved award to become `awarded`: (text, status to set now or None)."""
    if t.status in ("awarded", "paid"):
        return "done", None
    if t.status in ("patched", "disclosed") and t.visibility == "public":
        step = "set the status to awarded; this publishes it and lists the reporter on the leaderboard"
        return step, "awarded"
    if t.status in ("patched", "disclosed"):
        # `disclosed` and private: sealed again after its disclosure; disclosing it again unseals it
        return "disclose the report first (it is private), then set awarded", None
    if t.status == "closed":
        return "closed with an approved award: reopen it, or take the approval back", None
    return "the fix has not landed; awarded follows patched (or disclosed)", None


# Untold: nothing has been said on the ticket's thread since its status last moved. One definition, as
# SQL for the lists and as a check on one row read under its lock (`tell.tell_resting`).
UNTOLD = Ticket.told_at.is_(None) | (Ticket.told_at < Ticket.status_changed_at)


def untold(t: Ticket) -> bool:
    return t.status_changed_at is not None and (t.told_at is None or t.told_at < t.status_changed_at)


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
    q = q.where(UNTOLD)
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

_INTERNAL_REF = re.compile(r"(?:([a-z0-9][a-z0-9_.-]{0,19})?#)?([0-9]{1,9})")


def internal_ref(v: Any) -> str:
    """An engineering ticket reference as it is stored: `#1064` in the tracker, `faucet#10` in another
    repository. It is a key (the tracker's state follows `#n`, a class of reports is the tickets that
    share one, `settings.internal_url` links it), so it has one spelling: `1064`, `#1064`, ` #01064 `
    and `Faucet#10` are accepted and stored as `#1064` and `faucet#10`; anything else is a 400, where
    it used to be stored as sent and matched nothing, or was too long for the column and ended as a
    500. ASCII digits only: `str.isdigit` and `\\d` admit the other scripts' digits."""
    m = _INTERNAL_REF.fullmatch(v.strip().lower()) if isinstance(v, str) else None
    if m is None or int(m[2]) == 0:
        raise HTTPException(400, "internal_ref is a ticket number such as #1064 or faucet#10")
    return f"{m[1] or ''}#{int(m[2])}"


async def fact_value(db: AsyncSession, t: Ticket, k: str, v: Any) -> Any:
    """One fact as it would be stored on this ticket, or a 400: the vocabulary, the type, the one
    spelling of a value that is a key, and that what it names exists. `set_facts` stores what this
    returns, so a bad value never lands however it arrived; a proposal is checked with it when it is
    made, so an agent meets the 400 and not the person who would have adopted it (XE-1054)."""
    if k not in FACT_VOCAB:
        raise HTTPException(400, f"{k} is not a fact field")
    vocab = FACT_VOCAB[k]
    if k == "area":
        vocab = TOPICS if t.kind == "support" else AREAS
    if v in ("", None):
        if k == "visibility":
            raise HTTPException(400, "visibility is public or private")  # NOT NULL (XE-0973)
        return "" if k == "internal_ref" else None
    if vocab is not None and v not in vocab:
        raise HTTPException(400, f"{k} must be one of {list(vocab)}")
    if k == "claimed_tier" and t.kind != "bounty":
        raise HTTPException(400, "a support question carries no claimed tier")
    if k == "internal_ref":
        return internal_ref(v)
    if k == "duplicate_of":
        if not isinstance(v, str) or len(v) > 32:
            raise HTTPException(400, "duplicate_of is a ticket id such as XE-0042")
        v = v.strip().upper()
        if v == t.id:
            raise HTTPException(400, "a ticket cannot duplicate itself")
        if await get(db, v) is None:
            raise HTTPException(400, f"{v} does not exist")
    if k == "assignee_id":
        if isinstance(v, bool) or not isinstance(v, (int, str)) or not re.fullmatch(r"[0-9]{1,9}", str(v)):
            raise HTTPException(400, "assignee_id is a user id")
        v = int(v)
        if (await db.execute(select(User.id).where(User.id == v))).scalar_one_or_none() is None:
            raise HTTPException(400, "no such user")
    return v


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
    applied diff. Vocabulary is enforced here so a bad value never lands however it arrived. The row is
    locked first: what may change depends on the ticket's status (the tier behind an award, sealing an
    awarded report), and that is read as it is now (XE-0463)."""
    await lock(db, t)
    diff: dict[str, Any] = {}
    for k, v in changes.items():
        v = await fact_value(db, t, k, v)
        if k == "visibility" and v == "public" and t.visibility == "private":
            raise HTTPException(400, "use disclose to make a private ticket public")
        old = getattr(t, k)
        if old == v:
            continue
        if k == "assessed_tier" and t.award_approved_at and t.status not in ("awarded", "paid"):
            # the approval was for an amount under the old tier; it is taken back, the amount stays and
            # is re-checked against the new ceiling on the next approval (XE-0890)
            t.award_approved_by, t.award_approved_at = None, None
            diff["award_approved"] = {"from": True, "to": False}
        if k == "assessed_tier" and t.status in ("awarded", "paid"):
            raise HTTPException(409, f"the ticket is {t.status}; the tier behind the award stands")
        if k == "visibility" and v == "private":
            _award_is_public(t, visibility="private")
            text = t.body
            t.visibility = "private"
            set_body(ctx, t, text)
            await seal_thread(ctx, db, t)
            # the one public word on it from here: the ticket went private. Served whatever the ticket's
            # visibility is, so the public log explains why the rest of its history is gone (XE-0410,
            # XE-0350)
            await ctx.events.append(db, "ticket.sealed", p.actor, {"ticket": t.id}, ref=t.id, public=True)
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


async def lock(db: AsyncSession, t: Ticket) -> None:
    """Take the row lock on a ticket and re-read it, so the check that follows is against what is in the
    database now, not what this request read a moment ago (XE-0463). Pending changes are flushed first
    so nothing of this transaction is lost; the lock is held to commit."""
    await db.flush()
    await db.refresh(t, with_for_update=True)


async def as_it_is_now(db: AsyncSession, *rows) -> None:
    """Re-read rows a pass loaded a while ago, straight before a write to the outside that depends on
    them. The worker and the bot select their work once and then make one network call after another
    (a rate-limited GitHub call can sleep for minutes), on sessions that keep what they loaded; a
    ticket sealed meanwhile was still public in memory, its text still in clear, and the label, the
    comment or the disclosure issue was written (XE-0700 sweep). Pending changes are flushed first so
    none is lost. Not a row lock: that would hold a team member's seal behind a GitHub call; the
    window left is the one request."""
    await db.flush()
    for row in rows:
        await db.refresh(row)


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
    await lock(db, t)
    _award_is_public(t, status=status)
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
        if not ctx.vault.available:
            # the body has to leave the vault whole; without the key there is nothing to publish (XE-0791)
            raise HTTPException(503, "the vault key is not loaded; the ticket cannot be disclosed now")
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
        _check_ceiling(ctx, t, t.award_xe)
    if status == "paid" and not t.paid_ref and not force:
        raise HTTPException(400, "paid needs paid_ref")
    if not force and t.status == "paid" and status != "paid":
        raise HTTPException(409, "the ticket is paid; the record does not walk back")  # XE-0789
    if not force and t.status == "awarded" and status not in ("awarded", "paid", "closed"):
        raise HTTPException(409, "an awarded ticket is paid or closed, not walked back")
    old, old_reason = t.status, t.closed_reason
    if old == status and old_reason == closed_reason:
        if status == "disclosed" and t.visibility == "private":
            # sealed again after its disclosure (`set_facts` allows that): disclosing it again unseals
            # it, so the award that follows has a way through (the XE-2250 sweep). The status has not
            # moved, so nothing else is touched.
            await _unseal(ctx, db, p, t)
        return
    t.status = status
    t.closed_reason = closed_reason if status == "closed" else None
    t.status_changed_at = utcnow()
    t.queued = False  # a person (or the tracker) has reached it; the queue mark has done its job
    if status == "disclosed" and t.disclosed_at is None:
        t.disclosed_at = utcnow()
    if status == "disclosed" and t.visibility == "private":
        await _unseal(ctx, db, p, t)
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
    if status == "awarded":
        await _tell_awarded(ctx, db, p, t)


async def _unseal(ctx: Context, db: AsyncSession, p: Principal, t: Ticket) -> None:
    """The one disclosure path, whoever called: the body leaves the vault and the ticket goes public
    here, so a proposal, a walked path or a force can never leave a sealed ticket at "disclosed"."""
    try:
        text = ctx.vault.open_text(t.body_sealed) if t.body_sealed else ""
    except VaultError as e:
        raise HTTPException(503, f"the sealed body did not open: {e}") from e
    t.visibility = "public"
    t.body, t.body_sealed = text, None
    await ctx.events.append(
        db, "ticket.disclosed", p.actor, {"ticket": t.id, "title": t.title}, ref=t.id, public=True
    )


AWARD_STATUSES = ("awarded", "paid")


def _award_is_public(t: Ticket, *, status: str | None = None, visibility: str | None = None) -> None:
    """An awarded or paid ticket is public (XE-2250, XE-0911). `awarded` is the step that lists the
    reporter on the leaderboard and puts the ticket on the payment list, and from it the only move is
    `paid`, so a report awarded while sealed could never be disclosed; one sealed after its award left
    the leaderboard and stayed payable. Asked by the two writers that could break it, with what each is
    about to write: `set_status` (every path to a status, force included) and `set_facts` (the only
    path to private). A row that was both before this rule is left to be paid."""
    if (visibility or t.visibility) != "private" or (status or t.status) not in AWARD_STATUSES:
        return
    if t.visibility == "private" and t.status in AWARD_STATUSES:
        return
    if visibility:
        raise HTTPException(409, f"the ticket is {t.status}; an award is public and stays public")
    raise HTTPException(409, "the report is private; disclose it first, then mark it awarded")


async def _tell_awarded(ctx: Context, db: AsyncSession, p: Principal, t: Ticket) -> None:
    """A ticket just marked `awarded` tells its reporter: the programme's `awarded` reply, under the
    person who marked it, on the thread and out through the ticket's own channel (a GitHub comment, the
    chat thread, a mail once the request has committed: `notify.owe`). Called from `set_status` and
    nowhere else, so no path to `awarded` goes round it: the ticket page, settle, an adopted proposal.
    Two moves are left to the outbox instead: one with no person behind it (an import), which has no
    name to speak under, and an award of nothing, which the stock words do not fit."""
    tpl = ctx.config.reply_templates.get("awarded", "")
    if p.user is None or not t.award_xe or not tpl.strip():
        return
    from . import notify, thread

    draft = t.draft
    r = await thread.add_reply(ctx, db, p, t, await thread.fill_for(ctx, db, tpl, t))
    t.draft = draft  # a reply someone was writing on this ticket is still theirs to finish
    notify.owe(db, r)


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
    _award_is_public(t, status=status)  # before the first hop, not at the last one
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
    for r in (await db.execute(select(Reply).where(Reply.ticket_id == t.id))).scalars().all():
        if r.mirror == "queued":
            r.mirror = "none"
            n_rep += 1
        if r.body_sealed is None and r.body:
            r.body_sealed, r.body = ctx.vault.seal_text(r.body), ""  # XE-0426
    return {"messages": n_msg, "attachments": n_att, "replies_unqueued": n_rep}


async def disclose(ctx: Context, db: AsyncSession, p: Principal, t: Ticket) -> None:
    """Private → public. The work is in set_status (status `disclosed` unseals and flips visibility, and
    logs `ticket.disclosed`); the worker then opens the GitHub issue. Kept as the named entry point."""
    await set_status(ctx, db, p, t, "disclosed")


# An amount may be set from `accepted` on (the awards pass does that); approval waits for the fix.
AWARD_APPROVABLE_STATUSES = ("patched", "disclosed", "awarded", "paid")


AWARD_MAX = 1_000_000 * 1_000_000  # a million XE in micro-XE: no tier comes near it (XE-0973)


def _check_ceiling(ctx: Context, t: Ticket, award_xe: int | None) -> None:
    """An amount above zero needs an assessed tier and stays within twice that tier's ceiling (XE-0470,
    XE-0890). Zero (no award) is always allowed."""
    if not award_xe:
        return
    ceiling = ctx.config.ceiling_micro(t.assessed_tier)
    if not ceiling:
        raise HTTPException(409, "an award needs an assessed tier first; set the tier, then the amount")
    if award_xe > ceiling * 2:
        raise HTTPException(
            400, f"award exceeds twice the {t.assessed_tier} ceiling ({ceiling // 1_000_000:,} XE)"
        )


def award_approvable(t: Ticket) -> str | None:
    """None when the award may be approved now; otherwise the reason it may not, for the button and the 409."""
    if t.award_xe is None:
        return "nothing to approve"
    if t.status not in AWARD_APPROVABLE_STATUSES:
        return f"approval waits for the fix: the ticket is {t.status}, not patched or disclosed"
    return None


async def set_award(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    t: Ticket,
    award_xe: int | None,
    *,
    approve: bool | None = None,
    step: str | None = None,
) -> None:
    """Set the amount, approve it, or take approval back. `approve` None leaves approval as it is; True
    needs a set amount on a patched or disclosed ticket; False clears it (the amount stays). `step` names
    the award step the amount was taken from, when it was, so the log reads as a rule applied."""
    await lock(db, t)
    if award_xe is not None:
        if award_xe < 0:
            raise HTTPException(400, "award must be ≥ 0")
        if award_xe > AWARD_MAX:
            raise HTTPException(400, f"award must be at most {AWARD_MAX // 1_000_000:,} XE")
        if t.award_approved_at and award_xe != t.award_xe:
            raise HTTPException(409, "the award is approved; take approval back before changing the amount")
        if award_xe and t.status in ("awarded", "paid") and award_xe != t.award_xe:
            raise HTTPException(409, f"the ticket is {t.status}; the award stands")
        _check_ceiling(ctx, t, award_xe)
        t.award_xe = award_xe
    if approve is True:
        why = award_approvable(t)
        if why:
            raise HTTPException(409 if t.award_xe is not None else 400, why)
        _check_ceiling(ctx, t, t.award_xe)  # the tier may have moved since the amount was set (XE-0890)
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
            **({"step": step} if step else {}),
        },
        ref=t.id,
        public=t.visibility == "public",
    )


async def mark_paid(ctx: Context, db: AsyncSession, p: Principal, t: Ticket, paid_ref: str) -> None:
    """The treasurer records the payment: the reference goes on the ticket and it walks awarded → paid
    (XE-0737). The reference is a transaction hash or whatever the payer has; it is public with the
    ticket, like the amount."""
    ref = (paid_ref or "").strip()
    if not ref or len(ref) > 64 or not ref.isprintable():
        raise HTTPException(400, "paid_ref is 1 to 64 printable characters")
    await lock(db, t)  # of two recordings of one payment the second finds it paid (XE-0463)
    if t.status != "awarded":
        raise HTTPException(409, f"only an awarded ticket is paid; this one is {t.status}")
    t.paid_ref = ref
    await set_status(ctx, db, p, t, "paid", reason=f"paid: {ref[:64]}")


# ---- serialisation ----------------------------------------------------------------------------------


def ticket_url(ctx: Context, t: Ticket) -> str:
    """One canonical URL per ticket: the bare id at the root of its front door, e.g. https://bounty.xe.network/XE-0032."""
    base = f"{ctx.settings.scheme}://{ctx.settings.hosts['bounty' if t.kind == 'bounty' else 'support']}"
    return f"{base}/{t.id}"


def to_dict(
    ctx: Context, t: Ticket, p: Principal, *, with_body: bool = False, hidden: frozenset[str] = frozenset()
) -> dict:
    """`hidden` is `hidden_targets(...)` for the rows being serialised; a duplicate target in it is not
    named (XE-0799)."""
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
        "duplicate_of": t.duplicate_of if t.duplicate_of not in hidden else None,
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
    if full or (p.reporter_id and p.reporter_id == t.reporter_id):
        d["queued"] = t.queued  # the account's own pace is between it and the desk
    if full:
        d["draft"] = t.draft
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

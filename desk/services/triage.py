"""The triage doc, in and out.

`parse_triage` reads docs/BOUNTY_TRIAGE.md into rows with no database involved, so it is testable
against the real file. `import_rows` applies them: facts as facts (the doc is the team's ruling), the
italic note as an internal note by the triage agent token, PRs as patch refs, the Internal column as
status per brief §10. `export_markdown` writes the same tables back from the database.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import SYSTEM, Principal
from ..context import Context
from ..models import AgentToken, Note, Ticket, User
from . import thread
from . import tickets as tsvc
from .tickets import Filters, NewTicket

ISSUE_CELL = re.compile(r"\[(\d+)\]\((https?://github\.com/([\w.-]+/[\w.-]+)/issues/\d+)\)")
EMAIL_CELL = re.compile(r"^E(\d+)$")
ITALIC = re.compile(r"\*([^*]+)\*")
CODE = re.compile(r"`[^`]*`")

VERDICTS = {
    "valid": "valid",
    "likely valid": "likely-valid",
    "duplicate": "duplicate",
    "notice": "notice",
    "support": "support",
    "invalid": "invalid",
    "design gap": "design-gap",
    "out of scope": "out-of-scope",
}
GATES = {"before": "before", "later": "later", "decide": "decide"}
EFFORTS = {
    "<1h": "<1h",
    "1–4h": "1-4h",
    "1-4h": "1-4h",
    "½–1d": "half-1d",
    "1/2–1d": "half-1d",
    "1–3d": "1-3d",
    "1-3d": "1-3d",
    "3–5d": "3-5d",
    "3-5d": "3-5d",
    "1–2w": "1-2w",
    "1-2w": "1-2w",
    "design": "design",
}
TIER_WORDS = {
    "critical": "critical",
    "severe": "severe",
    "high": "high",
    "medium": "medium",
    "minor": "minor",
    "low": "minor",
    "none": "none",
}
SECTION_AREA = {
    "by email": None,
    "crashers": "consensus",
    "consensus": "consensus",
    "p2p / sync": "p2p-sync",
    "node / api": "node-api",
    "leasing / ledger": "leasing-ledger",
    "dao harness (ours)": "dao-harness",
    "sdk / docs / web": "sdk-docs-web",
    "ops / testnet, notices, support": "ops-testnet",
    "noise": "other",
}
EMAIL_AREA = {"E1": "consensus", "E2": "consensus", "E3": "node-api"}
INTERNAL_REF = re.compile(r"`((?:[\w-]+)?#\d+)`")
IMPORT_DATE = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


@dataclass
class PatchToken:
    repo: str
    ref: str
    note: str = ""


@dataclass
class Row:
    key: str  # "15" or "E1"
    repo: str = ""  # owner/repo for GitHub rows
    url: str = ""
    section: str = ""
    area: str | None = None
    title: str = ""
    note: str = ""
    verdict: str | None = None
    gate: str | None = None
    gate_note: str = ""
    duplicate_of_key: str | None = None
    claimed_tier: str | None = None
    assessed_tier: str | None = None
    assessed_word: str = ""  # the raw right-hand side: "dup of #14", "stale", "withdrawn", "Design"
    effort: str | None = None
    agent_effort: str = ""
    patches: list[PatchToken] = field(default_factory=list)
    internal_ref: str = ""
    internal_state: str = ""  # open | exists | partial | fixed | ""
    internal_fix_prs: list[str] = field(default_factory=list)
    first_reading: str = ""  # from the reconciliation table

    @property
    def is_email(self) -> bool:
        return self.key.startswith("E")

    # ---- derived -----------------------------------------------------------------------

    @property
    def kind(self) -> str:
        """Every triage row is a bounty ticket. "support" in the triage is a verdict (not a security bug,
        an operational or usage matter, closed as answered on the bounty), not a move to the support door:
        these are GitHub issues from researchers, and the support site is for holders and the community."""
        return "bounty"

    def status(self) -> tuple[str, str | None]:
        """(status, closed_reason) per brief §10."""
        w = self.assessed_word.lower()
        if self.verdict == "duplicate":
            return "closed", "duplicate"
        if self.verdict == "notice":
            return "closed", "answered"
        if self.verdict == "invalid":
            return "closed", "withdrawn" if "withdrawn" in w else "invalid"
        if self.verdict == "out-of-scope":
            return "closed", "out-of-scope"
        if self.verdict == "support":
            return "closed", "stale" if "stale" in w else "answered"
        if self.internal_state == "fixed":
            return "patched", None
        if self.internal_state == "partial":
            return "fixing", None
        if self.internal_ref:
            return "accepted", None
        return "triaging", None


# ---- parsing ----------------------------------------------------------------------------------------


def _cells(line: str) -> list[str]:
    masked = CODE.sub(lambda m: m.group(0).replace("|", "\x00"), line.strip().strip("|"))
    return [c.replace("\x00", "|").strip() for c in masked.split("|")]


def _plain(s: str) -> str:
    return s.replace("**", "").strip()


def _split_finding(text: str) -> tuple[str, str]:
    """Title and italic note. Code spans are masked so a `*` inside backticks is not emphasis."""
    masked = CODE.sub(lambda m: m.group(0).replace("*", "\x01"), text)
    notes = [n.strip() for n in ITALIC.findall(masked)]
    title = ITALIC.sub("", masked).replace("\x01", "*")
    title = re.sub(r"\s+", " ", title).strip().rstrip(".").strip()
    return title, " ".join(notes).replace("\x01", "*")


def _parse_tier(cell: str) -> tuple[str | None, str | None, str]:
    cell = _plain(cell)
    if "→" in cell:
        left, right = [s.strip() for s in cell.split("→", 1)]
    else:
        left, right = cell, ""
    claimed = TIER_WORDS.get(left.lower().split(",")[0].strip())
    assessed = TIER_WORDS.get(right.lower().split(",")[0].strip())
    return claimed, assessed, right


def _parse_gate(cell: str) -> tuple[str | None, str, str | None]:
    cell = _plain(cell)
    low = cell.lower()
    m = re.match(r"via\s+(#?\w+)", low)
    if m:
        return None, "", m.group(1).lstrip("#").upper()
    for word, gate in GATES.items():
        if low.startswith(word):
            note = cell[len(word) :].strip().strip("()").strip()
            return gate, note, None
    return None, "", None


def _parse_patches(cell: str, default_repo: str) -> list[PatchToken]:
    out: list[PatchToken] = []
    for part in re.split(r",\s*", _plain(cell)):
        part = part.strip()
        if not part or part == "—":
            continue
        m = re.match(r"((?:[\w.-]+/)?[\w.-]*#\d+)\s*(?:\((.*?)\))?$", part)
        if not m:
            continue
        parsed = thread.parse_patch_token(m.group(1), default_repo)
        if parsed:
            out.append(PatchToken(parsed[0], parsed[1], (m.group(2) or "").strip()))
    return out


def _parse_internal(cell: str) -> tuple[str, str, list[str]]:
    cell = cell.strip()
    if not cell or cell == "—":
        return "", "", []
    refs = INTERNAL_REF.findall(cell)
    low = cell.lower()
    state = (
        "fixed"
        if "fixed" in low
        else "partial"
        if "partial" in low
        else "exists"
        if "exists" in low
        else "open"
    )
    if not refs:
        return "", state if state == "fixed" else "", []
    return refs[0], state, refs[1:]


def parse_triage(text: str) -> list[Row]:
    rows: list[Row] = []
    section = ""
    in_every = False
    first_readings: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("## "):
            in_every = line[3:].strip().lower().startswith("every issue")
            section = ""
            continue
        if line.startswith("### "):
            section = line[4:].strip().lower()
            continue
        if not line.startswith("|"):
            continue
        cells = _cells(line)
        if not cells or cells[0] in ("#", "Item") or set(cells[0]) <= {"-", ":"}:
            continue
        # the reconciliation table, before the per-issue tables
        if not in_every and len(cells) == 3 and "→" in cells[1]:
            key = _row_key(cells[0])
            if key:
                first_readings[key] = f"{_plain(cells[1])}. {cells[2].strip()}"
            continue
        if not in_every:
            continue
        key = _row_key(cells[0])
        if key is None:
            continue
        r = Row(key=key, section=section, area=_area_for(section))
        m = ISSUE_CELL.search(cells[0])
        if m:
            r.url, r.repo = m.group(2), m.group(3)
        else:
            r.area = EMAIL_AREA.get(key, r.area)
        r.title, r.note = _split_finding(cells[1])
        r.verdict = VERDICTS.get(_plain(cells[2]).lower())
        if len(cells) >= 9:
            r.gate, r.gate_note, r.duplicate_of_key = _parse_gate(cells[3])
            r.claimed_tier, r.assessed_tier, r.assessed_word = _parse_tier(cells[4])
            r.effort = EFFORTS.get(_plain(cells[5]).lower().replace(" ", ""))
            r.agent_effort = _plain(cells[6])
            r.patches = _parse_patches(cells[7], r.repo or "xeprotocol/xe")
            r.internal_ref, r.internal_state, r.internal_fix_prs = _parse_internal(cells[8])
        elif len(cells) >= 4:
            r.internal_ref, r.internal_state, r.internal_fix_prs = _parse_internal(cells[3])
        if r.verdict in ("duplicate", "notice", "invalid", "support"):
            r.assessed_tier = None
        rows.append(r)
    for r in rows:
        r.first_reading = first_readings.get(r.key, "")
    return rows


def _row_key(cell: str) -> str | None:
    m = ISSUE_CELL.search(cell)
    if m:
        return m.group(1)
    m = EMAIL_CELL.match(cell.strip())
    return f"E{m.group(1)}" if m else None


def _area_for(section: str) -> str | None:
    """Section headings carry dates and asides ("By email, 28 October"); match on the leading words."""
    for prefix, area in SECTION_AREA.items():
        if section.startswith(prefix):
            return area
    return "other"


# ---- import -----------------------------------------------------------------------------------------


async def triage_token(ctx: Context, db: AsyncSession) -> AgentToken:
    """The agent token the import is attributed to. Created once, already expired, no scopes: it can
    never be used to call anything, it exists so the notes have an author."""
    ta = ctx.config.triage_agent
    q = select(AgentToken).where(AgentToken.model_id == ta["model_id"], AgentToken.label == ta["label"])
    tok = (await db.execute(q)).scalar_one_or_none()
    if tok:
        return tok
    owner = (await db.execute(select(User).order_by(User.id.asc()).limit(1))).scalar_one_or_none()
    if owner is None:
        raise RuntimeError("add a team user before importing the triage (desk users add ...)")
    tok = AgentToken(
        token_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        prefix="triage",
        owner_id=owner.id,
        model_id=ta["model_id"],
        label=ta["label"],
        scopes=[],
        expires_at=IMPORT_DATE,
        revoked_at=IMPORT_DATE,
    )
    db.add(tok)
    await db.flush()
    return tok


def _principal_for(tok: AgentToken) -> Principal:
    return Principal(kind="token", token=tok, scopes=set())


# The sheet is a snapshot. It may start a ticket off, walking the allowed path from where the ticket is,
# and it may still move one nobody has taken past triage. A ticket at `accepted` or beyond got there by a
# person's click, an internal ticket or a PR after the sheet was written; re-importing the sheet does not
# undo that (it once moved four awarded tickets back to accepted).
#
# Facts follow the same line (XE-2051). While the ticket is still in these statuses the sheet's value is
# written over the ticket's; past them the sheet only fills a fact that is still empty, so a tier, a
# verdict, a gate or a tracker link ruled since the sheet was written is not rolled back by importing it
# again. An empty cell never erases anything, at any status.
IMPORT_MOVES_FROM = ("new", "triaging", "needs-info")
EMPTY = ("", None)


async def import_rows(
    ctx: Context, db: AsyncSession, rows: list[Row], *, email_bodies: dict[str, str] | None = None
) -> dict:
    """Apply the rows. Tickets that the GitHub import created are updated; tickets it did not (no
    token, or the three emails) are created. Re-running is safe: notes are added once, and a status or
    a fact a person or GitHub has moved on since is left where it is (`IMPORT_MOVES_FROM`)."""
    tok = await triage_token(ctx, db)
    agent = _principal_for(tok)
    stats = {
        "rows": len(rows), "created": 0, "updated": 0, "notes": 0, "patches": 0, "skipped": 0,
        "status_kept": 0, "facts_kept": 0,
    }
    by_key: dict[str, Ticket] = {}

    # pass 1: tickets exist
    for r in rows:
        t = await _find(db, r)
        if t is None:
            t = await _create(ctx, db, r, (email_bodies or {}).get(r.key, ""))
            stats["created"] += 1
        by_key[r.key] = t

    # pass 2: facts, status, notes, patches
    for r in rows:
        t = by_key[r.key]
        owned = t.status in IMPORT_MOVES_FROM  # as the ticket stands before this row moves it
        changes: dict = {
            "area": r.area,
            "claimed_tier": r.claimed_tier,
            "assessed_tier": r.assessed_tier,
            "verdict": r.verdict,
            "mainnet_gate": r.gate,
            "effort_eng": r.effort,
            "internal_ref": r.internal_ref,
        }
        if r.duplicate_of_key and r.duplicate_of_key in by_key:
            changes["duplicate_of"] = by_key[r.duplicate_of_key].id
            if not r.internal_ref:
                changes["internal_ref"] = by_key[r.duplicate_of_key].internal_ref
        said = {k: v for k, v in changes.items() if v not in EMPTY}
        if r.kind != t.kind and not owned:
            # moved to the other door since: it has its own areas, and a question carries no claim
            said.pop("area", None)
            said.pop("claimed_tier", None)
        changes = {k: v for k, v in said.items() if owned or getattr(t, k) in EMPTY}
        if any(getattr(t, k) != v for k, v in said.items() if k not in changes):
            stats["facts_kept"] += 1
        if r.kind != t.kind and owned:
            await tsvc.set_kind(ctx, db, "desk", t, r.kind, via="triage")
        diff = await tsvc.set_facts(ctx, db, SYSTEM, t, changes, reason="triage import", via="triage")
        if diff:
            stats["updated"] += 1
        status, reason = r.status()
        if (t.status, t.closed_reason) != (status, reason):
            if t.status in IMPORT_MOVES_FROM and tsvc.status_path(t.kind, t.status, status) is not None:
                await tsvc.set_status_via_path(
                    ctx, db, SYSTEM, t, status, closed_reason=reason, reason="triage import", via="triage"
                )
            else:
                stats["status_kept"] += 1
        for ptk in r.patches:
            if await thread.add_patch_ref(ctx, db, SYSTEM, t, repo=ptk.repo, ref=ptk.ref, note=ptk.note):
                stats["patches"] += 1
        for pr in r.internal_fix_prs:
            parsed = thread.parse_patch_token(pr, ctx.config.primary_repo)
            if parsed and await thread.add_patch_ref(
                ctx, db, SYSTEM, t, repo=parsed[0], ref=parsed[1], note="fix", state="merged"
            ):
                stats["patches"] += 1
        note = _note_text(r)
        if note and not await _has_note(db, t, tok):
            n = await thread.add_note(ctx, db, agent, t, note)
            n.created_at = IMPORT_DATE
            stats["notes"] += 1
        if r.internal_state == "exists":
            await ctx.events.append(
                db,
                "ticket.internal_predates",
                "desk",
                {"ticket": t.id, "internal_ref": r.internal_ref},
                ref=t.id,
                public=t.visibility == "public",
            )
    await db.flush()
    return stats


def _note_text(r: Row) -> str:
    parts = []
    if r.note:
        parts.append(r.note)
    if r.first_reading:
        parts.append(f"First reading → ruling: {r.first_reading}")
    if r.gate_note:
        parts.append(f"Gate note: {r.gate_note}.")
    if r.agent_effort and r.agent_effort != "—":
        parts.append(f"Agent effort: {r.agent_effort}.")
    return "\n\n".join(parts).strip()


async def _find(db: AsyncSession, r: Row) -> Ticket | None:
    if r.is_email:
        return await tsvc.find_by_source(db, "email", "", r.key)
    return await tsvc.find_by_source(db, "github", r.repo, r.key)


async def _create(ctx: Context, db: AsyncSession, r: Row, body: str) -> Ticket:
    if r.is_email:
        spec = NewTicket(
            kind=r.kind,
            title=r.title,
            body=body or r.title,
            visibility="private",
            source="email",
            source_ref=r.key,
            area=r.area,
            claimed_tier=r.claimed_tier,
            source_created_at=IMPORT_DATE,
        )
    else:
        spec = NewTicket(
            kind=r.kind,
            title=r.title,
            body="",
            visibility="public",
            source="github",
            source_repo=r.repo,
            source_ref=r.key,
            source_url=r.url,
            area=r.area,
            claimed_tier=r.claimed_tier,
        )
    return await tsvc.create(ctx, db, "desk", spec)


async def _has_note(db: AsyncSession, t: Ticket, tok: AgentToken) -> bool:
    q = select(Note.id).where(Note.ticket_id == t.id, Note.author == f"token:{tok.id}").limit(1)
    return (await db.execute(q)).first() is not None


# ---- export -----------------------------------------------------------------------------------------

EFFORT_LABEL = {
    "<1h": "<1h",
    "1-4h": "1–4h",
    "half-1d": "½–1d",
    "1-3d": "1–3d",
    "3-5d": "3–5d",
    "1-2w": "1–2w",
    "design": "Design",
}


def _cell(s: str | None) -> str:
    """One table cell, one line (XE-0713): line breaks go, and a `|` cannot end the cell, nor a `\\`
    before one un-escape it. A cell that could break the row adds rows the heading does not count."""
    return " ".join((s or "").split()).replace("\\", "\\\\").replace("|", "\\|")


async def export_markdown(ctx: Context, db: AsyncSession, p: Principal) -> str:
    """The triage doc as the database has it now: the bounty's tickets, which are what a triage
    assesses. It is the assessment of every open ticket, which the desk does not publish, so it is
    written for the team and its agents and refused to anyone else here, whoever the caller is.
    Private tickets appear only for readers who may see them, and a duplicate's private target is not
    named to one who may not (`tickets.hidden_targets`). The number in the heading is the number of
    rows under it: every ticket is read once, in one statement, is in exactly one section, and each
    section is written once (XE-2271)."""
    if not tsvc.sees_assessment(p):
        raise HTTPException(403, "the triage export is the assessment of every open ticket; team and agents")
    cfg = ctx.config
    rows = await tsvc.every_ticket(db, cfg, p, Filters(kind="bounty", status="all"))
    hidden = await tsvc.hidden_targets(db, p, rows)
    now = datetime.now(timezone.utc)
    out = [
        f"# XE triage export, {now:%d %B %Y %H:%M} UTC",
        "",
        f"{len(rows)} tickets. Generated by the desk from its current state; the tables below follow "
        f"`docs/BOUNTY_TRIAGE.md`. Support tickets carry no assessment and are not in it.",
        "",
    ]
    patches: dict[str, list] = {}
    for t in rows:
        patches[t.id] = await thread.patches_for(db, t)
    # the sections are the configured areas, in their order; a ticket with no area, or one whose area
    # the configuration no longer names, is under Other
    sections = {**cfg.areas}
    sections.setdefault("other", "Other")
    by_area: dict[str, list[Ticket]] = {area: [] for area in sections}
    for t in rows:
        by_area[t.area if t.area in sections else "other"].append(t)
    for area, label in sections.items():
        ts = by_area[area]
        if not ts:
            continue
        out += [
            f"### {label}",
            "",
            "| # | Finding | Verdict | Mainnet | Tier | Eng. | Internal | Status | PR |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for t in ts:
            ref = f"[{t.source_ref}]({t.source_url})" if t.source == "github" and t.source_url else t.id
            tier = f"{cfg.tier_label(t.claimed_tier)} → {cfg.tier_label(t.assessed_tier)}"
            gate = {"before": "**Before**", "decide": "**Decide**", "later": "Later"}.get(
                t.mainnet_gate or "", "—"
            )
            if t.duplicate_of:
                gate = f"via {thread.UNNAMED_DUPLICATE if t.duplicate_of in hidden else t.duplicate_of}"
            prs = ", ".join(
                _cell(
                    f"{pr.repo.split('/')[-1] + '#' if pr.repo != cfg.primary_repo else '#'}{pr.ref}"
                    + (f" ({pr.note})" if pr.note else "")
                )
                for pr in patches[t.id]
            )
            status = t.status + (f" / {t.closed_reason}" if t.closed_reason else "")
            internal = f"`{t.internal_ref}`" if t.internal_ref else "—"
            title = _cell(t.title)
            out.append(
                f"| {ref} | {title} | {cfg.verdicts.get(t.verdict or '', t.verdict or '—')} | {gate} | {tier} | "
                f"{EFFORT_LABEL.get(t.effort_eng or '', '—')} | {internal} | {status} | {prs} |"
            )
        out.append("")
    return "\n".join(out)

"""Reports that arrived by email, brought onto the desk.

The desk reads no mailbox. A person goes through the one the reports were sent to, leaves out what is
not a report (marketing, a request for a key, a question about payment), and writes the rest to a JSON
file kept outside the repository: it carries private reports. `desk import-emails` then files each
mail as a private bounty ticket, `source: email`, with the mail's own id as `source_ref`, so a second
run over the same file adds nothing.

The sender is attached as the reporter by address (`reporters.attach`): the ticket, the team's replies
and the payout binding are theirs when they sign in with it. Nothing is sent to anyone from here, and
nothing a mail says about itself is taken as a fact: its tier is the sender's claim, a payout address
in its text stays text (an address is bound on the desk, by a signature), and its attachments are not
read, only named in a team note. The daily cap counts a mailed report as it counts one filed on the
form: past it the ticket is queued, so writing to the mailbox is not a way round the cap.

A mail that follows another (a correction, a retraction, more detail) is not a ticket of its own. With
`follows` naming the mail or the desk ticket it follows, its text is kept as a team note on that
ticket, saying whether it came from the reporter's address.

One item of the file:

    {"ref": "1a1dda665b2a0d98", "from_email": "a@example.org", "date": "2026-11-15T05:20:18Z",
     "subject": "...", "body": "...", "claimed_tier": "critical", "attachments": ["poc.zip"],
     "follows": ""}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import SYSTEM
from ..context import Context
from ..db import each_committed, passed_over
from ..models import Ticket
from . import reporters as rsvc
from . import thread
from . import tickets as tsvc

REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,95}")
TICKET = re.compile(r"[A-Za-z]{2}-\d{4,}")
MAX_BODY = 100_000  # a longer mail is read by a person first
MAX_NOTE = 19_000  # a follow-up is kept as a note, and a note holds 20k


@dataclass
class Mail:
    ref: str
    sender: str
    sent: datetime
    subject: str
    body: str
    tier: str | None = None
    attachments: list[str] = field(default_factory=list)
    follows: str = ""


def _text(v: Any, what: str, *, one_line: bool = False) -> str:
    if not isinstance(v, str):
        raise HTTPException(400, f"{what} is text")
    return tsvc.clean_text(v, one_line=one_line).strip()


def read(raw: Any) -> Mail:
    """One item of the file as the desk would keep it, or a 400 that says what is wrong with it."""
    if not isinstance(raw, dict):
        raise HTTPException(400, "an item is an object")
    ref = raw.get("ref")
    if not isinstance(ref, str) or not REF.fullmatch(ref):
        raise HTTPException(400, "ref is the mail's id: letters, digits and . _ : -, 3 to 96 of them")
    sender = rsvc.clean_email(raw.get("from_email") if isinstance(raw.get("from_email"), str) else "")
    try:
        sent = datetime.fromisoformat(str(raw.get("date") or "").replace("Z", "+00:00"))
    except ValueError:
        sent = None
    if sent is None or sent.tzinfo is None:
        raise HTTPException(400, "date is when the mail was sent, ISO 8601 with its offset")
    subject = _text(raw.get("subject"), "subject", one_line=True)
    if len(subject) < 3:
        raise HTTPException(400, "subject is the mail's subject, three characters or more")
    body = _text(raw.get("body"), "body")
    if not body:
        raise HTTPException(400, "body is the mail's text")
    if len(body) > MAX_BODY:
        raise HTTPException(400, f"body is over {MAX_BODY:,} characters; file this one by hand")
    names = raw.get("attachments") or []
    if not isinstance(names, list) or len(names) > 50:
        raise HTTPException(400, "attachments is a list of file names, 50 at most")
    follows = raw.get("follows") or ""
    if not isinstance(follows, str) or (follows and not REF.fullmatch(follows)):  # a ticket id fits REF
        raise HTTPException(400, "follows is the ref of another mail or a ticket id")
    tier = tsvc.claimed(raw.get("claimed_tier") if isinstance(raw.get("claimed_tier"), str) else None)
    return Mail(
        ref=ref,
        sender=sender,
        sent=sent,
        subject=subject,
        body=body,
        tier=None if tier == "none" else tier,  # as the form stores it
        attachments=[_text(n, "an attachment's name", one_line=True)[:200] for n in names],
        follows=follows,
    )


def _when(m: Mail) -> str:
    return m.sent.strftime("%Y-%m-%d %H:%M %Z").strip()


def _provenance(m: Mail) -> str:
    """The team note on an imported ticket: where the body came from and what did not come with it."""
    lines = [
        f"Imported from the security mailbox (mail {m.ref}), sent {_when(m)}. The body is the mail's "
        "text as it arrived; the original stays in the mailbox.",
        "The tier is the sender's claim. A payout address in the text is not bound: the reporter binds "
        "one on the desk, signed in.",
    ]
    if m.attachments:
        lines.append("Attached to the mail, not imported and not opened: " + ", ".join(m.attachments) + ".")
    return "\n\n".join(lines)


def _marker(m: Mail) -> str:
    return f"By email (mail {m.ref}), sent {_when(m)}"


async def _followed(db: AsyncSession, m: Mail) -> Ticket | None:
    """The ticket a follow-up belongs on: named by id, or the one made for the mail it follows."""
    if TICKET.fullmatch(m.follows):
        return await tsvc.get(db, m.follows)
    return await tsvc.find_by_source(db, "email", "", m.follows)


async def _follow_up(ctx: Context, db: AsyncSession, m: Mail, t: Ticket, dry_run: bool) -> dict:
    marker = _marker(m)
    if any(n.body.startswith(marker) for n in await thread.notes_for(db, t)):
        return {"ref": m.ref, "ticket": t.id, "note": "already there"}
    owner = await rsvc.get(db, t.reporter_id) if t.reporter_id else None
    theirs = owner is not None and owner.email == m.sender
    who = "from the reporter's address" if theirs else "from an address that is NOT the reporter's on record"
    text = m.body
    if len(text) > MAX_NOTE:
        text = text[:MAX_NOTE] + "\n\n[cut here; the rest is in the mailbox]"
    names = f"\n\nAttached to the mail, not imported: {', '.join(m.attachments)}." if m.attachments else ""
    if not dry_run:
        await thread.add_note(ctx, db, SYSTEM, t, f"{marker}, {who}. Subject: {m.subject}\n\n{text}{names}")
    return {"ref": m.ref, "ticket": t.id, "note": "added", "from_reporter": theirs}


async def import_emails(ctx: Context, db: AsyncSession, items: list[Any], *, dry_run: bool = False) -> dict:
    """File each mail of an export. Reports first, then the mails that follow one, so a follow-up finds
    the ticket made in the same run. Each item is its own savepoint, committed before the next
    (`each_committed`): one the desk refuses is listed under `skipped` with the reason and the rest
    go through. `existing` are the ones a previous run
    filed. With `dry_run` nothing is written and `created` says what would be."""
    out: dict[str, list[dict]] = {"created": [], "existing": [], "notes": [], "skipped": []}
    mails: list[Mail] = []
    seen: set[str] = set()
    for i, raw in enumerate(items):
        ref = raw.get("ref") if isinstance(raw, dict) and isinstance(raw.get("ref"), str) else f"item {i}"
        try:
            m = read(raw)
            if m.ref in seen:
                raise HTTPException(400, "the same ref is in the file twice")
            seen.add(m.ref)
            mails.append(m)
        except HTTPException as e:
            out["skipped"].append({"ref": ref[:96], "why": str(e.detail)})
    planned = {m.ref for m in mails if not m.follows}  # what a dry run would have filed by then
    async for m in each_committed(db, sorted(mails, key=lambda x: bool(x.follows))):
        try:
            if m.follows:
                t = await _followed(db, m)
                if t is None and dry_run and m.follows in planned:
                    on = f"the ticket for mail {m.follows}"
                    out["notes"].append({"ref": m.ref, "ticket": on, "note": "added"})
                    continue
                if t is None:
                    raise HTTPException(400, f"follows {m.follows}, which is not on the desk")
                async with db.begin_nested():
                    out["notes"].append(await _follow_up(ctx, db, m, t, dry_run))
                continue
            t = await tsvc.find_by_source(db, "email", "", m.ref)
            if t is not None:
                out["existing"].append({"ref": m.ref, "ticket": t.id})
                continue
            known = await rsvc.by_email(db, m.sender)
            row = {"ref": m.ref, "ticket": None, "reporter": known.id if known else None,
                   "tier": m.tier, "chars": len(m.body), "title": m.subject[:80]}
            if not dry_run:
                async with db.begin_nested():
                    spec = tsvc.NewTicket(
                        kind="bounty",
                        title=m.subject,
                        body=m.body,
                        visibility="private",
                        source="email",
                        source_ref=m.ref,
                        claimed_tier=m.tier,
                        source_created_at=m.sent,
                    )
                    t = await tsvc.create(ctx, db, SYSTEM.actor, spec)
                    r = await rsvc.attach(ctx, db, SYSTEM, t, email=m.sender)
                    # the daily cap is the reporter's whichever door the report came through
                    queued = await rsvc.queue_past_cap(ctx, db, r, t)
                    await thread.add_note(ctx, db, SYSTEM, t, _provenance(m))
                    row.update(ticket=t.id, reporter=r.id, queued=queued)
            out["created"].append(row)
        except HTTPException as e:
            out["skipped"].append({"ref": m.ref, "why": str(e.detail)})
        except Exception as e:
            out["skipped"].append({"ref": m.ref, "why": passed_over(f"filing mail {m.ref}", e)})
    return out

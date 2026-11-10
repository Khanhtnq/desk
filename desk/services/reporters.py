"""Reporters: the people who file.

An account is one row in `reporters` holding up to three identities: a GitHub login (which also claims
the tickets imported from GitHub under that login), an email, and an XE address proven by signature.
A payout address is bound by a second signature under its own domain, so the address on a ticket is one
the reporter has shown they control; nothing here is ever pasted into a thread.

Filing: a bounty report with a claimed tier of Critical or Severe, or the "keep it private" box ticked,
is private: body and attachments sealed with the vault key, nothing mirrored to GitHub until a Reviewer
discloses it. The box is the reporter's and is read here; the tier rule is `tickets.create`'s, for every
writer. The reporter gets the ticket id at once.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from fastapi import HTTPException, UploadFile
from sqlalchemy import case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.keys import KeyError_, KeyPair, derive_address

from ..auth import Verified, clean_lookup, drop_reporter_links, family_lock
from ..authz import Principal
from ..context import Context
from ..models import AREAS, TOPICS, Attachment, Reporter, ReporterSession, Ticket
from . import thread
from . import tickets as tsvc
from .tickets import NewTicket, utcnow

log = logging.getLogger("desk.reporters")

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
OPEN_FOR_REPORTER = ("new", "triaging", "needs-info", "accepted", "fixing")


# ---- lookups ----------------------------------------------------------------------------------------


async def get(db: AsyncSession, rid: int) -> Reporter | None:
    return (await db.execute(select(Reporter).where(Reporter.id == rid))).scalar_one_or_none()


async def by_github(db: AsyncSession, github_id: int | None, login: str) -> Reporter | None:
    if github_id is not None:
        r = (await db.execute(select(Reporter).where(Reporter.github_id == github_id))).scalar_one_or_none()
        if r:
            return r
    if login:
        # a login claims a row only while no GitHub identity has signed in to it; a row bound to another
        # github_id is someone else's, however the login was recycled
        q = (
            select(Reporter)
            .where(Reporter.github_login == login, Reporter.github_id.is_(None))
            .order_by(Reporter.id)
        )
        return (await db.execute(q)).scalars().first()
    return None


async def by_email(db: AsyncSession, email: str) -> Reporter | None:
    email = clean_lookup(email).lower()
    if not email:
        return None
    q = select(Reporter).where(Reporter.email == email).order_by(Reporter.id)
    return (await db.execute(q)).scalars().first()


async def by_login_address(db: AsyncSession, address: str) -> Reporter | None:
    q = select(Reporter).where(Reporter.xe_login_addresses.contains([address])).order_by(Reporter.id)
    return (await db.execute(q)).scalars().first()


async def identity_lock(db: AsyncSession, *keys: str) -> None:
    """A transaction-scoped advisory lock on an identity about to be looked up and perhaps created, so two
    first sign-ins with the same key, login or email in the same second make one row, not two
    (XE-0969, XE-1012). Postgres only; released with the transaction."""
    for k in keys:
        if k:
            await family_lock(db, f"reporter:{k}")


def _name(s: str) -> str:
    return tsvc.clean_text(s, one_line=True)[:128]


def clean_email(email: str) -> str:
    e = (email or "").strip().lower()
    if not EMAIL.match(e) or len(e) > 256 or e != tsvc.clean_text(e, one_line=True):
        raise HTTPException(400, "that does not look like an email address")
    return e


# ---- the team attaches a reporter ------------------------------------------------------------------------


def label(r: Reporter) -> str:
    """How a reporter is named in team-facing lists."""
    local = r.email.split("@")[0] if r.email else ""
    who = r.display_name or r.github_login or local or f"reporter {r.id}"
    via = r.email or (f"@{r.github_login}" if r.github_login else "") or r.xe_address[:12]
    return f"{who} ({via})" if via and via != who else who


async def list_for_picker(db: AsyncSession, limit: int = 300) -> list[Reporter]:
    q = select(Reporter).order_by(Reporter.display_name, Reporter.github_login, Reporter.email).limit(limit)
    return list((await db.execute(q)).scalars().all())


async def attach(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    t: Ticket,
    *,
    reporter_id: int | None = None,
    email: str | None = None,
) -> Reporter:
    """Put a reporter on a ticket that arrived without one (an emailed report, a triage import). Either an
    existing reporter, or an email: the desk finds the reporter with that email or creates one, so that when
    they sign in with it their tickets and payout binding are already there. Logged with the old value.
    Whether the ticket may still move depends on its award and status, read under the row lock."""
    await tsvc.lock(db, t)
    if reporter_id is not None:
        r = (await db.execute(select(Reporter).where(Reporter.id == reporter_id))).scalar_one_or_none()
        if r is None:
            raise HTTPException(404, "no such reporter")
        how = "picked"
    elif email:
        e = clean_email(email)
        r = await by_email(db, e)
        how = "email"
        if r is None:
            r = Reporter(email=e, display_name=_name(e.split("@")[0]))
            db.add(r)
            await db.flush()
            await ctx.events.append(
                db, "reporter.created", p.actor, {"how": "team", "ticket": t.id}, public=False
            )
            how = "email-new"
    else:
        raise HTTPException(400, "give a reporter_id or an email")
    if t.reporter_id == r.id:
        return r
    if t.award_approved_at is not None or t.status in ("awarded", "paid"):
        # who is paid is settled with the award; moving the ticket afterwards is the treasurer's call
        # and the stamp follows (XE-0351)
        from ..authz import can

        if not can(p, "award", t):
            raise HTTPException(409, "the award is approved; only a treasurer moves the ticket now")
        if t.status == "paid":
            raise HTTPException(409, "the ticket is paid; the reporter on record stands")
    prev = t.reporter_id
    t.reporter_id = r.id
    if t.kind == "bounty":
        t.payout_address = r.xe_address
    await ctx.events.append(
        db,
        "ticket.reporter",
        p.actor,
        {"ticket": t.id, "from": prev, "to": r.id, "how": how},
        ref=t.id,
        public=False,
    )
    return r


# ---- sign-in: find or create, and link -------------------------------------------------------------------


async def from_github(
    ctx: Context, db: AsyncSession, gh_user: dict, email: str, *, link_to: Reporter | None
) -> Reporter:
    """The GitHub identity claims the imported reporter row with that login, so their old issues show up
    under "my reports" the first time they sign in."""
    gid = int(gh_user["id"])
    # what a provider says of an account is text from outside like any other, and this is where it is
    # written: the login, the name and the address are made storable here, for every caller (the
    # OAuth callback parses GitHub's JSON itself, not through `github.storable`)
    login = tsvc.clean_text(gh_user.get("login"), one_line=True)[:128]
    email = tsvc.clean_text(email, one_line=True).lower()[:256]
    await identity_lock(db, f"github:{gid}", f"email:{email}" if email else "")
    existing = await by_github(db, gid, login)
    if existing is None and email:
        # the provider vouched for the address: a row already holding it (an emailed report the team
        # attached, an email sign-in) is this person, provided no other GitHub identity has it (XE-1012)
        held = await by_email(db, email)
        if held is not None and held.github_id is None:
            existing = held
    r = link_to or existing
    if r is None:
        name = _name(gh_user.get("name") or login)
        r = Reporter(github_login=login, github_id=gid, email=email, display_name=name)
        db.add(r)
        await db.flush()
        await ctx.events.append(db, "reporter.created", f"reporter:{r.id}", {"how": "github"}, public=False)
        return r
    if existing is not None and existing.id != r.id:
        await merge(ctx, db, into=r, other=existing)
    if r.github_id is not None and r.github_id != gid:
        raise HTTPException(409, "this account already has a different GitHub identity")
    r.github_id, r.github_login = gid, login or r.github_login
    if not r.display_name:
        r.display_name = _name(gh_user.get("name") or login)
    if email and not r.email:
        r.email = email
    return r


async def from_email(ctx: Context, db: AsyncSession, email: str, *, link_to: Reporter | None) -> Reporter:
    email = clean_email(email)
    await identity_lock(db, f"email:{email}")
    existing = await by_email(db, email)
    r = link_to or existing
    if r is None:
        r = Reporter(email=email, display_name=_name(email.split("@")[0]))
        db.add(r)
        await db.flush()
        await ctx.events.append(db, "reporter.created", f"reporter:{r.id}", {"how": "email"}, public=False)
        return r
    if existing is not None and existing.id != r.id:
        # the clicker proved the mailbox, not the other account: mail never merges
        raise HTTPException(409, "that address is already on another account; sign in there to use it")
    r.email = email
    return r


async def from_xe(ctx: Context, db: AsyncSession, v: Verified, *, link_to: Reporter | None) -> Reporter:
    await identity_lock(db, f"xe:{v.account}")
    existing = await by_login_address(db, v.account)
    r = link_to or existing
    if r is None:
        r = Reporter(display_name=f"xe:{v.account[:8]}", xe_login_addresses=[v.account])
        db.add(r)
        await db.flush()
        await ctx.events.append(db, "reporter.created", f"reporter:{r.id}", {"how": "xe"}, public=False)
        return r
    if existing is not None and existing.id != r.id:
        await merge(ctx, db, into=r, other=existing)
    if v.account not in (r.xe_login_addresses or []):
        r.xe_login_addresses = [*(r.xe_login_addresses or []), v.account]
    return r


async def merge(ctx: Context, db: AsyncSession, *, into: Reporter, other: Reporter) -> None:
    """Two rows turn out to be one person (an imported GitHub login signs in by email first, say): the
    tickets move, the identities union, the other row is kept empty rather than deleted so its id in
    old log entries still resolves."""
    for t in (await db.execute(select(Ticket).where(Ticket.reporter_id == other.id))).scalars():
        t.reporter_id = into.id
    into.github_id = into.github_id or other.github_id
    into.github_login = into.github_login or other.github_login
    into.email = into.email or other.email
    into.display_name = into.display_name or other.display_name
    if not into.xe_address and other.xe_address:
        into.xe_address, into.payout_proof = other.xe_address, other.payout_proof
    into.xe_login_addresses = sorted(set(into.xe_login_addresses or []) | set(other.xe_login_addresses or []))
    # platform ids move too, so the chat bot keys later messages to the live row, not the shell (XE-0473)
    into.platform_ids = {**(other.platform_ids or {}), **(into.platform_ids or {})}
    other.platform_ids = {}
    was = other.email
    other.github_id, other.github_login, other.email = None, "", ""
    other.xe_address, other.payout_proof, other.xe_login_addresses = "", {}, []
    other.display_name = f"merged into {into.id}"
    await db.flush()
    await restamp(db, into)  # moved tickets carry the surviving account's address (XE-0801)
    # the shell keeps no way in: its sessions and outstanding links end with the merge (XE-0710). Its
    # links are the ones bound to it and the ones mailed to its address: a plain sign-in link carries
    # no account, only the address, and one sent before the merge outlived it, signing its holder in
    # as that address again, on a new row, after the merge had folded the address away (XE-1904)
    await db.execute(delete(ReporterSession).where(ReporterSession.reporter_id == other.id))
    await drop_reporter_links(db, reporter_id=other.id, email=was)
    await ctx.events.append(
        db, "reporter.merged", f"reporter:{into.id}", {"into": into.id, "other": other.id}, public=False
    )


# ---- taking a way in off an account -----------------------------------------------------------------------


def ways_in(r: Reporter) -> int:
    """How many independent ways this account can still be signed in to."""
    n = len(r.xe_login_addresses or [])
    n += 1 if r.email else 0
    n += 1 if r.github_id is not None else 0
    n += sum(1 for k in (r.platform_ids or {}) if not k.endswith("_handle"))
    return n


async def unlink(ctx: Context, db: AsyncSession, r: Reporter, kind: str, value: str = "") -> dict:
    """Take one identity off the account (XE-0575, XE-0812): an XE login key, the email, GitHub or a chat
    platform. The last way in stays; the payout address is separate and untouched."""
    if ways_in(r) <= 1:
        raise HTTPException(409, "that is the only way into this account; add another first")
    value = (value or "").strip().lower()
    if kind == "xe":
        if value not in (r.xe_login_addresses or []):
            raise HTTPException(404, "that key is not on this account")
        r.xe_login_addresses = [a for a in r.xe_login_addresses if a != value]
    elif kind == "email":
        if not r.email:
            raise HTTPException(404, "no email is on this account")
        value, r.email = r.email, ""
        await drop_reporter_links(db, email=value)  # mail already sent to it is not a way back (XE-1904)
    elif kind == "github":
        if r.github_id is None:
            raise HTTPException(404, "GitHub is not linked")
        value, r.github_id, r.github_login = r.github_login, None, ""
    elif kind in (r.platform_ids or {}):
        ids = dict(r.platform_ids)
        value = ids.pop(kind, "")
        ids.pop(f"{kind}_handle", None)
        r.platform_ids = ids
    else:
        raise HTTPException(400, "kind is xe, email, github or a linked platform")
    await ctx.events.append(
        db, "reporter.unlinked", f"reporter:{r.id}", {"kind": kind, "value": value}, public=False
    )
    return {"kind": kind, "ways_in": ways_in(r)}


async def end_other_sessions(db: AsyncSession, r: Reporter, keep: int | None) -> int:
    """Sign the account out everywhere but here. Outstanding email links for it die too."""
    q = delete(ReporterSession).where(ReporterSession.reporter_id == r.id)
    if keep is not None:
        q = q.where(ReporterSession.id != keep)
    res = await db.execute(q)
    await drop_reporter_links(db, reporter_id=r.id)
    return int(res.rowcount or 0)


# ---- the payout address -------------------------------------------------------------------------------


async def bind_payout(ctx: Context, db: AsyncSession, r: Reporter, v: Verified) -> dict:
    """The reporter signed {"address": A} under xe/desk/payout/v1 with the key that derives to A. The
    address goes on the account and on every open ticket of theirs that has none yet."""
    address = str(v.payload.get("address") or "").lower()
    if address != v.account:
        raise HTTPException(400, "the address in the payload is not the one this key derives to")
    if address in await _public_as_seed(db, r):
        # An XE address is 64 hex, the same shape as a seed. Paste one into the seed field and the browser
        # derives a key from it; anyone who knows the address can do the same and spend the award.
        raise HTTPException(
            400,
            "that key was made from a public address used as a seed, so anyone who knows the address could "
            "spend from it. Paste the seed, not the address, or make a new key.",
        )
    r.xe_address = address
    r.payout_proof = {"pub_key": v.pub_key, "signature": v.signature, "timestamp": v.timestamp}
    n = await restamp(db, r)
    await ctx.events.append(
        db,
        "reporter.payout_bound",
        f"reporter:{r.id}",
        {"address": address, "tickets": n},  # the proof itself lives on the row, not in the log
        public=False,
    )
    return {"address": address, "tickets_updated": n}


async def restamp(db: AsyncSession, r: Reporter) -> int:
    """Put the reporter's current payout address on every bounty ticket of theirs not yet paid; a rebind
    replaces the earlier stamp, it does not leave it (XE-0711, XE-0801). Returns how many changed."""
    n = 0
    q = select(Ticket).where(Ticket.reporter_id == r.id, Ticket.kind == "bounty", Ticket.status != "paid")
    for t in (await db.execute(q)).scalars():
        if t.payout_address != r.xe_address:
            t.payout_address = r.xe_address
            n += 1
    return n


async def _public_as_seed(db: AsyncSession, r: Reporter) -> set[str]:
    """Addresses that would result from using one of this reporter's public strings as a seed: their
    sign-in addresses, their current payout address and any address already on their tickets."""
    known = set(r.xe_login_addresses or []) | {r.xe_address}
    q = select(Ticket.payout_address).where(Ticket.reporter_id == r.id, Ticket.payout_address != "")
    known |= {a for (a,) in (await db.execute(q)).all()}
    out = set()
    for a in known:
        if a and re.fullmatch(r"[0-9a-f]{64}", a):
            out.add(KeyPair.from_seed_hex(a).address)
    return out


async def unbind_payout(ctx: Context, db: AsyncSession, r: Reporter) -> dict:
    """Take the payout address off the account and off every ticket of theirs that is not yet paid."""
    if not r.xe_address:
        raise HTTPException(409, "no payout address is bound")
    old = r.xe_address
    r.xe_address = ""
    r.payout_proof = {}
    n = await restamp(db, r)
    await ctx.events.append(
        db, "reporter.payout_unbound", f"reporter:{r.id}", {"address": old, "tickets": n}, public=False
    )
    return {"tickets_updated": n}


def check_address(address: str) -> str:
    a = (address or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", a):
        raise HTTPException(400, "an XE address is 64 hex characters")
    return a


def address_of(pub_key_hex: str) -> str:
    try:
        return derive_address(pub_key_hex)
    except KeyError_ as e:
        raise HTTPException(400, str(e)) from e


# ---- filing -----------------------------------------------------------------------------------------


@dataclass
class Filing:
    kind: str = "bounty"
    title: str = ""
    body: str = ""
    area: str | None = None
    claimed_tier: str | None = None
    private: bool = False
    files: list[UploadFile] = field(default_factory=list)


async def file_ticket(ctx: Context, db: AsyncSession, r: Reporter, f: Filing) -> Ticket:
    title = (f.title or "").strip()
    body = (f.body or "").strip()
    if len(title) < 8:
        raise HTTPException(400, "give the report a title of at least eight characters")
    if len(title) > 200:
        raise HTTPException(400, "the title is too long (200 characters)")
    if len(body) < 40:
        raise HTTPException(400, "say more: what you did, what happened, what you expected (40 characters at least)")
    if len(body) > 60_000:
        raise HTTPException(400, "the report is too long (60k); attach the rest")
    if f.kind not in ("bounty", "support"):
        raise HTTPException(400, "kind must be bounty or support")
    area = f.area if f.area in (TOPICS if f.kind == "support" else AREAS) else None
    tier = tsvc.claimed(f.claimed_tier) if f.kind == "bounty" else None
    if len(f.files) > ctx.settings.max_attachments:
        raise HTTPException(400, f"at most {ctx.settings.max_attachments} attachments")
    t = await tsvc.create(
        ctx,
        db,
        f"reporter:{r.id}",
        NewTicket(
            kind=f.kind,
            title=title,
            body=body,
            # the box is the reporter's choice; Critical and Severe are private whatever it says, and
            # that is `create`'s rule (XE-1932)
            visibility="private" if f.kind == "bounty" and f.private else "public",
            source="web",
            reporter_id=r.id,
            area=area,
            claimed_tier=None if tier == "none" else tier,
        ),
    )
    if f.kind == "bounty" and r.xe_address:
        t.payout_address = r.xe_address
    if f.kind == "bounty":
        await queue_past_cap(ctx, db, r, t)
    for up in f.files:
        await save_attachment(ctx, db, t, up, actor=f"reporter:{r.id}")
    return t


async def filed_today(db: AsyncSession, r: Reporter, *, before: Ticket | None = None) -> int:
    """How many bounty reports this reporter filed in the last rolling day, not counting `before`."""
    cut = utcnow() - timedelta(hours=24)
    q = select(func.count()).select_from(Ticket).where(
        Ticket.reporter_id == r.id, Ticket.kind == "bounty", Ticket.created_at >= cut
    )
    if before is not None:
        q = q.where(Ticket.id != before.id)
    return int((await db.execute(q)).scalar_one())


async def queue_past_cap(ctx: Context, db: AsyncSession, r: Reporter, t: Ticket) -> bool:
    """Mark `t` queued when the reporter has already filed `intake.daily_cap` reports in the last day.
    The report is kept whole; it sorts after everything else and the reporter is told the earlier ones
    are read first. A scanner filing forty probes in a morning stops costing the queue; one account
    filing its tenth real finding of the day is not refused anything."""
    cap = ctx.config.daily_cap
    if not cap:
        return False
    n = await filed_today(db, r, before=t)
    if n < cap:
        return False
    t.queued = True
    await ctx.events.append(
        db,
        "ticket.queued",
        f"reporter:{r.id}",
        {"ticket": t.id, "filed_today": n + 1, "cap": cap},
        ref=t.id,
        public=False,
    )
    return True


# ---- attachments ------------------------------------------------------------------------------------


def _blob_path(ctx: Context, t: Ticket, n: int, filename: str) -> Path:
    safe = SAFE_NAME.sub("_", filename)[:80] or "file"
    return Path(ctx.settings.blob_dir) / t.id / f"{n:02d}-{safe}"


async def save_attachment(
    ctx: Context, db: AsyncSession, t: Ticket, up: UploadFile, *, actor: str
) -> Attachment:
    limit = ctx.settings.max_attachment_mb * 1024 * 1024
    # the name as the client sent it is cleaned once, for the row and for the two refusals: a
    # multipart part is decoded with the charset the client names, so it can carry half a surrogate
    # pair, and an error response with one in it cannot be encoded (a 500 where a 400 was meant)
    name = tsvc.clean_text(up.filename, one_line=True)[:256]
    data = await up.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"{name or 'attachment'} is over {ctx.settings.max_attachment_mb} MB")
    if not data:
        raise HTTPException(400, f"{name or 'attachment'} is empty")
    last = select(Attachment.n).where(Attachment.ticket_id == t.id).order_by(Attachment.n.desc())
    n = int((await db.execute(last)).scalars().first() or 0) + 1
    sealed = t.visibility == "private"
    path = _blob_path(ctx, t, n, name or "file")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ctx.vault.seal(data) if sealed else data)
    a = Attachment(
        ticket_id=t.id,
        n=n,
        filename=name or "file",
        content_type=(tsvc.clean_text(up.content_type, one_line=True) or "application/octet-stream")[:128],
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        blob_path=str(path.relative_to(ctx.settings.blob_dir)),
        sealed=sealed,
    )
    db.add(a)
    await db.flush()
    await ctx.events.append(
        db,
        "attachment.added",
        actor,
        {"ticket": t.id, "n": n, "size": a.size, "sha256": a.sha256, "sealed": sealed},
        ref=t.id,
        public=not sealed,
    )
    return a


async def attachments_for(db: AsyncSession, t: Ticket) -> list[Attachment]:
    q = select(Attachment).where(Attachment.ticket_id == t.id).order_by(Attachment.n)
    return list((await db.execute(q)).scalars())


async def open_attachment(
    ctx: Context, db: AsyncSession, p: Principal, t: Ticket, n: int
) -> tuple[Attachment, bytes]:
    """The caller has checked the reader may see the ticket. Opening a sealed attachment is logged, so
    "who has seen this exploit" has an answer."""
    q = select(Attachment).where(Attachment.ticket_id == t.id, Attachment.n == n)
    a = (await db.execute(q)).scalar_one_or_none()
    if a is None:
        raise HTTPException(404, "no such attachment")
    path = Path(ctx.settings.blob_dir) / a.blob_path
    if not path.exists():
        raise HTTPException(410, "the attachment's blob is missing")
    raw = path.read_bytes()
    data = ctx.vault.open(raw) if a.sealed else raw
    if a.sealed:
        await ctx.events.append(
            db,
            "attachment.read",
            p.actor,
            {"ticket": t.id, "n": n, "sha256": a.sha256},
            ref=t.id,
            public=False,
        )
    return a, data


# ---- what a reporter may do to their own ticket -----------------------------------------------------------


def owns(r: Reporter | None, t: Ticket) -> bool:
    return r is not None and t.reporter_id == r.id


async def my_tickets(db: AsyncSession, r: Reporter) -> list[Ticket]:
    q = select(Ticket).where(Ticket.reporter_id == r.id).order_by(Ticket.created_at.desc())
    return list((await db.execute(q)).scalars())


PAYOUT_COLUMNS = (
    "ticket", "title", "status", "tier", "award_xe", "approved_at", "reporter_id", "reporter", "xe_address",
    "stamped_address",
)


async def payout_rows(db: AsyncSession) -> list[dict]:
    """Awards still to pay: bounty tickets at `awarded` with an approved amount, oldest approval first.
    The one source for the treasurer's JSON and CSV (XE-0711, XE-0801): `xe_address` is the reporter's
    live bound address (blank when none is bound), `stamped_address` the one on the ticket, which a
    rebind or merge has refreshed; when they differ the list says so and the live one is paid. Closed
    and paid tickets are not payable and never appear."""
    q = (
        select(Ticket, Reporter)
        .outerjoin(Reporter, Reporter.id == Ticket.reporter_id)
        .where(
            Ticket.kind == "bounty",
            Ticket.status == "awarded",
            Ticket.award_approved_at.is_not(None),
            Ticket.award_xe.is_not(None),
            Ticket.paid_ref == "",
        )
        .order_by(Ticket.award_approved_at)
    )
    out: list[dict] = []
    for t, r in (await db.execute(q)).all():
        live = r.xe_address if r else ""
        out.append(
            {
                "ticket": t.id,
                "title": t.title,
                "status": t.status,
                "tier": t.assessed_tier or "",
                "award_xe": t.award_xe or 0,
                "approved_at": t.award_approved_at.isoformat() if t.award_approved_at else "",
                "reporter_id": r.id if r else None,
                "reporter": (r.display_name or r.github_login or r.email) if r else "",
                "xe_address": live,
                "stamped_address": t.payout_address,
                "address_changed": bool(t.payout_address) and t.payout_address != live,
            }
        )
    return out


def csv_cell(v) -> str:
    """A spreadsheet reads a leading =, +, -, @ or a tab/CR as a formula or a control; reporter-written
    text gets a leading apostrophe so it stays text (XE-0714)."""
    s = "" if v is None else str(v)
    if s and s[0] in "=+-@\t\r":
        return "'" + s
    return s


async def withdraw(ctx: Context, db: AsyncSession, r: Reporter, t: Ticket, reason: str = "") -> None:
    """The reporter closes their own open ticket. The status is read under the row lock, and the move
    is an ordinary one (every status in OPEN_FOR_REPORTER may close), so a ticket the team patched,
    awarded or paid a moment ago is not closed over the top of that (XE-1960 sweep)."""
    if not owns(r, t):
        raise HTTPException(403, "not your ticket")
    await tsvc.lock(db, t)
    if t.status not in OPEN_FOR_REPORTER:
        raise HTTPException(409, f"a {t.status} ticket cannot be withdrawn")
    p = Principal(kind="reporter", reporter_id=r.id)
    closed_reason = "withdrawn" if t.kind == "bounty" else "answered"
    await tsvc.set_status(ctx, db, p, t, "closed", closed_reason=closed_reason, reason=reason[:500])


async def reply(ctx: Context, db: AsyncSession, r: Reporter, t: Ticket, body: str):
    """The reporter's own word on their ticket, from the desk's reply box. A finished ticket (closed or
    paid) takes none: the rule is here, where the message is written, and the ticket page asks the same
    question of the same property to decide whether to show the box (XE-1960). The question is asked
    of the row as it is now, under its lock, not as this request read it: a reply racing the close
    lands before it or is refused."""
    if not owns(r, t):
        raise HTTPException(403, "not your ticket")
    await tsvc.lock(db, t)
    if not t.is_open:
        raise HTTPException(409, f"a {t.status} ticket takes no more messages; file a new one")
    body = (body or "").strip()
    if not body:
        raise HTTPException(400, "empty message")
    if len(body) > 20_000:
        raise HTTPException(400, "message too long (20k)")
    m = await thread.add_message(
        ctx,
        db,
        t,
        source="web",
        source_ref=f"reporter:{r.id}:{secrets.token_hex(8)}",
        author=r.display_name or r.github_login or r.email or f"reporter {r.id}",
        body=body,
    )
    if t.status == "needs-info":
        # the reporter answered; back to the team
        await tsvc.set_status(
            ctx, db, Principal(kind="reporter", reporter_id=r.id), t, "triaging", reason="reporter replied"
        )
    t.updated_at = utcnow()
    return m


async def records(db: AsyncSession, ids: set[int]) -> dict[int, dict]:
    """What the desk knows about each reporter's filings, for the ticket page and the triage row: how many
    filed, how many ruled real or duplicate or noise, how many awarded, how many still unread, how many
    in the last day. A reviewer reads a tenth report from an account differently from a first."""
    ids = {i for i in ids if i}
    if not ids:
        return {}
    real = Ticket.verdict.in_(("valid", "likely-valid"))
    noise = Ticket.verdict.in_(("invalid", "notice", "support", "out-of-scope"))
    cut = utcnow() - timedelta(hours=24)
    one = lambda cond: func.sum(case((cond, 1), else_=0))  # noqa: E731
    q = (
        select(
            Ticket.reporter_id,
            func.count(),
            one(real),
            one(Ticket.verdict == "duplicate"),
            one(noise),
            one(Ticket.status.in_(("awarded", "paid"))),
            one(Ticket.status == "new"),
            one(Ticket.created_at >= cut),
            one(Ticket.queued.is_(True)),
        )
        .where(Ticket.reporter_id.in_(ids), Ticket.kind == "bounty")
        .group_by(Ticket.reporter_id)
    )
    out: dict[int, dict] = {}
    for rid, n, real_n, dup, noise_n, awarded, unread, day, queued in (await db.execute(q)).all():
        out[rid] = {
            "filed": int(n), "real": int(real_n), "duplicate": int(dup), "noise": int(noise_n),
            "awarded": int(awarded), "unread": int(unread), "today": int(day), "queued": int(queued),
        }
    return out


def to_dict(r: Reporter) -> dict:
    return {
        "id": r.id,
        "display_name": r.display_name,
        "github_login": r.github_login,
        "email": r.email,
        "xe_address": r.xe_address,
        "payout_bound": bool(r.xe_address),
        "login_addresses": r.xe_login_addresses or [],
        "claimed_at": r.claimed_at.isoformat() if r.claimed_at else None,
    }

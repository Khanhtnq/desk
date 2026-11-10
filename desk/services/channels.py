"""Chat channels as ticket sources: Discord now, Telegram in the same shape later.

Everything a bot needs that touches the database lives here, so the bot module is only the platform
glue and this part is tested against Postgres without a gateway connection. The brief (§11) names four
things a channel bot does: create, thread, reply, status. In order:

- `open_from_channel`: a message or a form in the channel becomes a `support` ticket with `source` and
  `source_ref` (the thread id), owned by a reporter keyed on their platform id.
- `incoming`: later messages in the thread append to the ticket's public thread.
- `queued_replies` / `mark_mirrored`: a public reply written on the desk is posted into the thread by the
  bot, attributed to the human who wrote it. Agent notes never leave the desk.
- `needing_state_push` / `mark_state`: closing on the desk archives the thread; the bot says why.

Conversion to a bounty ticket is here too, with the one rule that matters: no proof of concept in chat.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import SYSTEM
from ..context import Context
from ..models import TOPICS, Reply, Reporter, Ticket
from . import reporters as rsvc
from . import thread
from . import tickets as tsvc
from .tickets import NewTicket, utcnow

CHANNELS = ("discord", "telegram")


# ---- reporters keyed on a platform id -----------------------------------------------------------------


async def by_platform(db: AsyncSession, platform: str, pid: str) -> Reporter | None:
    q = select(Reporter).where(Reporter.platform_ids[platform].astext == str(pid)).order_by(Reporter.id)
    return (await db.execute(q)).scalars().first()


async def from_platform(
    ctx: Context,
    db: AsyncSession,
    platform: str,
    pid: str,
    *,
    name: str,
    handle: str = "",
    email: str = "",
    link_to: Reporter | None = None,
) -> Reporter:
    """The reporter behind a platform account; created on first contact. With `link_to` (a signed-in web
    reporter adding the platform to their account) the platform identity moves onto that account and
    any platform-only row merges into it."""
    email = (email or "").lower()[:256]
    await rsvc.identity_lock(db, f"{platform}:{pid}", f"email:{email}" if email else "")
    existing = await by_platform(db, platform, pid)
    if existing is None and email:
        # the platform vouched for the address; a row that holds it without this platform is the same
        # person (XE-1012)
        held = await rsvc.by_email(db, email)
        if held is not None and platform not in (held.platform_ids or {}):
            existing = held
    r = link_to or existing
    if r is None:
        r = Reporter(display_name=(name or handle or f"{platform}:{pid}")[:128], platform_ids={})
        db.add(r)
        await db.flush()
        await ctx.events.append(db, "reporter.created", f"reporter:{r.id}", {"how": platform}, public=False)
    elif existing is not None and existing.id != r.id:
        await rsvc.merge(ctx, db, into=r, other=existing)
    ids = dict(r.platform_ids or {})
    ids[platform] = str(pid)
    if handle:
        ids[f"{platform}_handle"] = handle
    r.platform_ids = ids
    if not r.display_name or r.display_name.startswith(f"{platform}:"):
        r.display_name = (name or handle or r.display_name)[:128]
    if email and not r.email:
        r.email = email
    return r


# ---- create -----------------------------------------------------------------------------------------


@dataclass
class ChannelPost:
    platform: str  # discord | telegram
    thread_ref: str  # the thread/topic id the conversation lives in
    thread_url: str
    user_id: str
    user_name: str
    user_handle: str = ""
    title: str = ""
    body: str = ""
    topic: str | None = None


async def ticket_for(db: AsyncSession, platform: str, thread_ref: str) -> Ticket | None:
    q = select(Ticket).where(Ticket.source == platform, Ticket.source_ref == str(thread_ref))
    return (await db.execute(q)).scalar_one_or_none()


async def open_from_channel(ctx: Context, db: AsyncSession, post: ChannelPost) -> Ticket:
    if post.platform not in CHANNELS:
        raise HTTPException(400, "unknown channel")
    title = (post.title or "").strip()[:200] or (post.body or "").strip().split("\n", 1)[0][:200]
    body = (post.body or "").strip()
    if len(title) < 4:
        raise HTTPException(400, "a question needs a few words")
    r = await from_platform(
        ctx, db, post.platform, post.user_id, name=post.user_name, handle=post.user_handle
    )
    t = await tsvc.create(
        ctx,
        db,
        f"reporter:{r.id}",
        NewTicket(
            kind="support",
            title=title,
            body=body,
            visibility="public",
            source=post.platform,
            source_ref=str(post.thread_ref),
            source_url=post.thread_url,
            reporter_id=r.id,
            area=post.topic if post.topic in TOPICS else None,
        ),
    )
    t.channel_state = "open"
    await ctx.events.append(
        db,
        f"{post.platform}.opened",
        f"reporter:{r.id}",
        {"ticket": t.id, "thread": str(post.thread_ref)},
        ref=t.id,
    )
    return t


# ---- thread -----------------------------------------------------------------------------------------


async def incoming(
    ctx: Context,
    db: AsyncSession,
    t: Ticket,
    *,
    message_ref: str,
    user_id: str,
    user_name: str,
    body: str,
    is_team: bool,
    attachments: list[str] | None = None,
):
    """A message in the ticket's thread. Idempotent on the platform message id. The reporter answering a
    `needs-info` puts the ticket back in triage; the team's first word on a `new` one starts it."""
    text = (body or "").strip()
    if attachments:
        text = (text + "\n\n" if text else "") + "\n".join(f"Attachment: {u}" for u in attachments)
    if not text:
        return None
    # the two status moves below are decided on the row as it is now (XE-1960 sweep): read stale, a
    # `needs-info` ticket closed a moment ago would be put back in triage by the answer. Taken before
    # anything is written, so the order is the ticket row and then the log, as in `set_status`.
    await tsvc.lock(db, t)
    m = await thread.add_message(
        ctx,
        db,
        t,
        source=t.source,
        source_ref=str(message_ref),
        author=user_name,
        body=text[:20_000],
        is_team=is_team,
    )
    if m is None:
        return None
    if is_team:
        thread.mark_told(t)  # the team's own words in the thread tell the asker, as a desk reply does
    via = f"{t.source}:{user_id}"
    if is_team and t.status == "new":
        await tsvc.set_status(ctx, db, SYSTEM, t, "triaging", reason="team replied in the thread", via=via)
    elif not is_team and t.status == "needs-info":
        r = await by_platform(db, t.source, user_id)
        if r is not None and r.id == t.reporter_id:
            await tsvc.set_status(ctx, db, SYSTEM, t, "triaging", reason="reporter replied", via=via)
    t.updated_at = utcnow()
    return m


# ---- the team acting from the channel --------------------------------------------------------------------


async def close_from_channel(ctx: Context, db: AsyncSession, t: Ticket, *, user_id: str, reason: str) -> str:
    """`/close` in the thread. Reason words map onto the support closed reasons; anything else is `answered`
    and the words go in the log."""
    words = (reason or "").strip()
    low = words.lower()
    closed_reason = "answered"
    if low.startswith("stale"):
        closed_reason = "stale"
    elif low.startswith("dup"):
        closed_reason = "duplicate"
    await tsvc.lock(db, t)
    if closed_reason == "duplicate" and not t.duplicate_of:
        closed_reason = "answered"
    if t.kind == "bounty" and t.status not in ("new", "triaging", "needs-info"):
        # a thread command closes a question; a report that the team has accepted, or that carries an
        # award, is closed from the desk by the person responsible (XE-0690, XE-0805)
        raise HTTPException(409, f"{t.id} is a {t.status} bounty report; close it on the desk")
    await tsvc.set_status(
        ctx,
        db,
        SYSTEM,
        t,
        "closed",
        closed_reason=closed_reason,
        reason=words[:500],
        via=f"{t.source}:{user_id}",
    )
    t.channel_state = "closed"
    return closed_reason


async def reopen_from_channel(ctx: Context, db: AsyncSession, t: Ticket, *, user_id: str) -> None:
    if t.status in ("closed", "paid"):
        await tsvc.set_status(
            ctx, db, SYSTEM, t, "triaging", reason="reopened from the thread", via=f"{t.source}:{user_id}"
        )
    t.channel_state = "open"


async def convert_to_bounty(ctx: Context, db: AsyncSession, t: Ticket, *, user_id: str) -> None:
    """A question that is really a bug. The id and the history stay; the area is cleared because topics are
    not engineering areas; the bot tells the reporter where it went and not to post a PoC in the thread."""
    if t.kind == "bounty":
        raise HTTPException(409, "already a bounty ticket")
    t.kind = "bounty"
    t.area = None
    t.updated_at = utcnow()
    await ctx.events.append(
        db,
        "ticket.kind",
        "desk",
        {"ticket": t.id, "from": "support", "to": "bounty", "via": f"{t.source}:{user_id}"},
        ref=t.id,
        public=t.visibility == "public",
    )


async def rename_from_channel(ctx: Context, db: AsyncSession, t: Ticket, *, user_id: str, title: str) -> str:
    title = (title or "").strip()[:200]
    if len(title) < 4:
        raise HTTPException(400, "a title needs a few words")
    old, t.title = t.title, title
    t.updated_at = utcnow()
    await ctx.events.append(
        db,
        "ticket.renamed",
        "desk",
        {"ticket": t.id, "from": old, "to": title, "via": f"{t.source}:{user_id}"},
        ref=t.id,
        public=t.visibility == "public",
    )
    return title


# ---- reply and status, desk → channel ------------------------------------------------------------------


async def queued_replies(db: AsyncSession, platform: str, limit: int = 50) -> list[tuple[Reply, Ticket]]:
    q = (
        select(Reply, Ticket)
        .join(Ticket, Ticket.id == Reply.ticket_id)
        .where(Reply.mirror == "queued", Ticket.source == platform, Ticket.visibility == "public")
        .order_by(Reply.created_at.asc())
        .limit(limit)
    )
    return [(r, t) for r, t in (await db.execute(q)).all()]


def reply_text(ctx: Context, t: Ticket, r: Reply) -> str:
    """How a desk reply reads in the channel: the person's name, the words, the ticket link as a footnote."""
    body = thread.reply_body(ctx, r)
    return f"**{r.author_name or 'XE team'}** · XE team\n{body}\n-# {t.id} · {tsvc.ticket_url(ctx, t)}"


async def mark_mirrored(
    ctx: Context, db: AsyncSession, r: Reply, t: Ticket, *, message_ref: str, url: str = ""
) -> None:
    r.mirror, r.mirror_ref, r.mirror_error, r.sent_at = "sent", url or message_ref, "", utcnow()
    await thread.reply_carried(ctx, db, t, r, source=t.source, source_ref=str(message_ref))
    t.last_public_at = utcnow()
    await ctx.events.append(
        db, "reply.mirrored", "desk", {"ticket": t.id, "reply": r.id, "url": r.mirror_ref}, ref=t.id
    )


async def mark_failed(ctx: Context, db: AsyncSession, r: Reply, t: Ticket, error: str) -> None:
    r.mirror, r.mirror_error = "failed", error[:2000]
    await ctx.events.append(
        db, "reply.mirror_failed", "desk", {"ticket": t.id, "reply": r.id, "error": error[:200]}, ref=t.id
    )


async def needing_state_push(db: AsyncSession, platform: str) -> list[Ticket]:
    """Tickets whose desk status and channel state disagree: closed here but the thread is open, or the
    reverse after a reopen. Public ones only: what the desk decides about a sealed ticket is not written
    to its thread, as its replies are not (`queued_replies`; XE-0700)."""
    q = select(Ticket).where(
        Ticket.source == platform, Ticket.source_ref != "", Ticket.visibility == "public"
    )
    out = []
    for t in (await db.execute(q)).scalars():
        want = "closed" if t.status in ("closed", "paid") else "open"
        if t.channel_state != want:
            out.append(t)
    return out


def wanted_state(t: Ticket) -> str:
    return "closed" if t.status in ("closed", "paid") else "open"


async def mark_state(ctx: Context, db: AsyncSession, t: Ticket, state: str) -> None:
    t.channel_state = state
    await ctx.events.append(
        db, f"{t.source}.state_pushed", "desk", {"ticket": t.id, "state": state}, ref=t.id, public=True
    )


# ---- what the bot says --------------------------------------------------------------------------------


def bot_text(ctx: Context, key: str, t: Ticket | None = None, **extra: str) -> str:
    """A line from the public register's `bots` block, with the ticket filled in. Linted like all public
    copy, so a bot can never promise anything."""
    tpl = str((ctx.config.copy_public.get("bots") or {}).get(key, ""))
    values = {"ticket_id": t.id if t else "", "ticket_url": tsvc.ticket_url(ctx, t) if t else "", **extra}
    try:
        return tpl.format(**values)
    except (KeyError, IndexError):
        return tpl


def closed_line(ctx: Context, t: Ticket, reason: str = "") -> str:
    label = ctx.config.copy_public.get("labels", {}).get(t.closed_reason or "", t.closed_reason or "closed")
    text = f"{label}{': ' + reason if reason else ''}"
    return bot_text(ctx, "closed", t, reason=text)

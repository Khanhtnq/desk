"""Telling the reporter. A private report's thread is only visible on the desk, so without this a reporter
who signed in with a key would have to come back and look. One rule: when the team replies and the
account has a confirmed email, mail it. Chat-sourced tickets are told in their thread by the bot instead.
Mail never blocks or fails the reply; a miss is logged.

A route that sends a reply mails it itself once it has committed. A reply the desk sends on its own
account inside a service (a ticket marked awarded) has no route to do that, so the service notes it on
the session (`owe`) and the request's session dependency mails what was committed (`mail_owed`)."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import auth
from ..context import Context
from ..models import Reply, Reporter, Ticket
from .tickets import ticket_url

# the chat sources; the bot tells those threads itself (channels.CHANNELS, not imported: thread imports us)
CHAT = ("discord", "telegram")

log = logging.getLogger("desk.notify")

OWED = "owed_mail"  # key in the session's info: ids of replies to mail once the request commits


def owe(db: AsyncSession, r: Reply) -> None:
    """Note a reply to be mailed to its reporter after the request's transaction commits."""
    db.sync_session.info.setdefault(OWED, []).append(r.id)


def take_owed(db: AsyncSession) -> list[int]:
    """The reply ids noted on this session, taken off it."""
    return list(db.sync_session.info.pop(OWED, []))


async def mail_owed(ctx: Context, ids: list[int], opener=None) -> int:
    """Mail the reporter of each noted reply. The replies are read through a session of their own, so
    only what was committed is found: one whose savepoint or request rolled back is not there and is
    not mailed. `opener` makes that session (the app's own by default). Never raises; a miss is
    logged. Returns how many mails went out."""
    if not ids:
        return 0
    from ..db import session
    from . import thread

    sent = 0
    try:
        async with (opener or session)() as db:
            q = select(Reply).where(Reply.id.in_(ids)).order_by(Reply.id.asc())
            for r in (await db.execute(q)).scalars().all():
                t = (await db.execute(select(Ticket).where(Ticket.id == r.ticket_id))).scalar_one_or_none()
                if t is None:
                    continue
                # a private ticket's mail carries the fact and the link only, so its reply stays sealed
                text = thread.reply_body(ctx, r) if t.visibility == "public" else ""
                sent += int(await reply_to_reporter(ctx, db, t, r.author_name, text))
    except Exception:
        log.exception("owed mail not sent for replies %s", ids)
    return sent


async def reply_to_reporter(ctx: Context, db: AsyncSession, t: Ticket, author: str, body: str) -> bool:
    """Mail the reporter about a team reply on `t`. Private tickets get the fact and the link, not the
    text; public ones get the text as well. Returns whether a mail went out."""
    if t.source in CHAT or not t.reporter_id or not ctx.settings.smtp_host:
        return False
    r = (await db.execute(select(Reporter).where(Reporter.id == t.reporter_id))).scalar_one_or_none()
    if r is None or not r.email:
        return False
    url = ticket_url(ctx, t)
    noun = "question" if t.kind == "support" else "report"
    subject = f"{t.id}: {author} replied"
    if t.visibility == "public":
        text = f"{author} replied to your {noun} {t.id}, {t.title}:\n\n{body}\n\nFollow it at {url}"
    else:
        text = (
            f"{author} replied to your private {noun} {t.id}. The thread is only readable on the desk, "
            f"signed in as you:\n\n{url}"
        )
    sent = await auth.send_mail(ctx.settings, r.email, subject, text)
    if not sent:
        log.warning("reply on %s not mailed to reporter %s", t.id, r.id)
    return sent

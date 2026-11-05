"""The two threads on a ticket and the patch list.

messages   the public thread: imported comments, reporter messages, our mirrored replies
notes      internal; humans and agent tokens; never leaves the desk
replies    public; human author only; queued for the worker to mirror to the source channel
patch_refs PRs and commits
"""

from __future__ import annotations

import re
from datetime import timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import Principal
from ..context import Context
from ..models import Message, Note, PatchRef, Reply, Ticket
from .tickets import utcnow

REPO_ALIASES = {
    "": "xeprotocol/xe",
    "xe": "xeprotocol/xe",
    "dao": "xeprotocol/dao",
    "sdk": "xeprotocol/sdk",
    "faucet": "xeprotocol/faucet",
}
PR_TOKEN = re.compile(r"(?:(?P<owner>[\w.-]+)/)?(?P<repo>[\w.-]*)#(?P<num>\d+)")


# ---- notes ------------------------------------------------------------------------------------------


CHECKED_KEYS = {"desk": int, "similar": list, "tracker": bool, "tree": str}


def clean_checked(raw: dict | None) -> dict:
    """`checked` as stored: the four known keys with the right types, nothing else, ids upper-cased."""
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise HTTPException(400, "checked is an object")
    out: dict = {}
    for k, v in raw.items():
        want = CHECKED_KEYS.get(k)
        if want is None:
            raise HTTPException(400, f"checked: unknown key {k!r}; use {sorted(CHECKED_KEYS)}")
        if isinstance(v, bool) and want is not bool or not isinstance(v, want):
            raise HTTPException(400, f"checked.{k} is a {want.__name__}")
        if k == "similar":
            v = [str(x).upper() for x in v if str(x).strip()][:50]
        if k == "tree":
            v = v.strip()[:200]
        out[k] = v
    return out


async def add_note(
    ctx: Context, db: AsyncSession, p: Principal, t: Ticket, body: str, checked: dict | None = None
) -> Note:
    body = (body or "").strip()
    if not body:
        raise HTTPException(400, "empty note")
    if len(body) > 20_000:
        raise HTTPException(400, "note too long (20k)")
    n = Note(ticket_id=t.id, author=p.actor, author_name=p.name, body=body, checked=clean_checked(checked))
    db.add(n)
    await db.flush()
    await ctx.events.append(
        db,
        "note.added",
        p.actor,
        {"ticket": t.id, "note": n.id, "chars": len(body)},
        ref=t.id,
        public=t.visibility == "public",
    )
    return n


async def notes_for(db: AsyncSession, t: Ticket) -> list[Note]:
    return list(
        (await db.execute(select(Note).where(Note.ticket_id == t.id).order_by(Note.created_at.asc())))
        .scalars()
        .all()
    )


# ---- public thread ----------------------------------------------------------------------------------


async def messages_for(db: AsyncSession, t: Ticket) -> list[Message]:
    q = select(Message).where(Message.ticket_id == t.id).order_by(Message.created_at.asc())
    return list((await db.execute(q)).scalars().all())


async def add_message(
    ctx: Context,
    db: AsyncSession,
    t: Ticket,
    *,
    source: str,
    source_ref: str,
    author: str,
    body: str,
    created_at=None,
    is_team: bool = False,
) -> Message | None:
    """Append to the public thread; idempotent on (source, source_ref). Private tickets seal the body."""
    if source_ref:
        exists = (
            await db.execute(
                select(Message).where(Message.source == source, Message.source_ref == source_ref)
            )
        ).scalar_one_or_none()
        if exists:
            return None
    m = Message(
        ticket_id=t.id, source=source, source_ref=source_ref, author=author[:128], author_is_team=is_team
    )
    if t.visibility == "private":
        if not ctx.vault.available:
            raise HTTPException(503, "the vault key is not loaded")
        m.body_sealed = ctx.vault.seal_text(body)
    else:
        m.body = body
    if created_at is not None:
        m.created_at = created_at
    db.add(m)
    await db.flush()
    return m


def message_body(ctx: Context, t: Ticket, m: Message) -> str:
    if m.body_sealed:
        try:
            return ctx.vault.open_text(m.body_sealed)
        except Exception:
            return "[sealed]"
    return m.body


# ---- replies ----------------------------------------------------------------------------------------


async def add_reply(ctx: Context, db: AsyncSession, p: Principal, t: Ticket, body: str) -> Reply:
    body = (body or "").strip()
    if not body:
        raise HTTPException(400, "empty reply")
    if p.user is None:
        raise HTTPException(403, "only a person sends a public reply")
    # Mirrored when the source channel can carry it: a GitHub comment, a message in the Discord thread.
    # The worker handles GitHub; each bot handles its own channel.
    mirror = "queued" if t.source in ("github", "discord", "telegram") and t.visibility == "public" else "none"
    r = Reply(ticket_id=t.id, author_id=p.user.id, author_name=p.name, body=body, mirror=mirror)
    db.add(r)
    t.last_public_at = utcnow()
    t.told_at = utcnow()
    t.draft = ""
    await db.flush()
    # a reply is part of the public thread. When it is mirrored, the worker adds the GitHub comment
    # itself (with the comment id, so the webhook echo is not a second copy); otherwise it goes in now.
    if mirror == "none":
        await add_message(
            ctx, db, t, source="desk", source_ref=f"reply:{r.id}", author=p.name, body=body, is_team=True
        )
    await ctx.events.append(
        db,
        "reply.sent",
        p.actor,
        {"ticket": t.id, "reply": r.id, "mirror": mirror, "chars": len(body)},
        ref=t.id,
        public=t.visibility == "public",
    )
    return r


async def replies_for(db: AsyncSession, t: Ticket) -> list[Reply]:
    return list(
        (await db.execute(select(Reply).where(Reply.ticket_id == t.id).order_by(Reply.created_at.asc())))
        .scalars()
        .all()
    )


def render_template(ctx: Context, name: str, t: Ticket, **extra: str) -> str:
    """A reply template from the public register, with the ticket's facts filled in. The result is a draft
    in the editor, never a sent reply."""
    return fill(ctx, ctx.config.reply_templates.get(name, ""), t, **extra)


def fill(ctx: Context, tpl: str, t: Ticket, **extra: str) -> str:
    """`{ticket_url}`, `{tier}`, `{duplicate_url}` and the rest filled in from the ticket. Used for the
    public templates and for an agent's reply draft alike, so a draft can name the ticket without knowing
    its front door. Text that is not a template (a stray brace) comes back as it was."""
    from .tickets import ticket_url

    values = {
        "ticket_url": ticket_url(ctx, t),
        "tier": ctx.config.tier_label(t.assessed_tier),
        "duplicate_url": ticket_url(ctx, t).rsplit("/", 1)[0] + "/" + (t.duplicate_of or ""),
        "patch_refs": extra.pop("patch_refs", "the linked PR"),
        "what": extra.pop("what", "a reproduction"),
        "reason": extra.pop("reason", ""),
        "answer": extra.pop("answer", "(the answer goes here)"),
    }
    values.update(extra)
    try:
        return tpl.format(**values)
    except (KeyError, IndexError):
        return tpl


# ---- patch refs -------------------------------------------------------------------------------------


def parse_patch_token(token: str, default_repo: str) -> tuple[str, str] | None:
    """'#27' -> (xeprotocol/xe, 27); 'dao#1' -> (xeprotocol/dao, 1); 'owner/repo#5' -> (owner/repo, 5)."""
    m = PR_TOKEN.fullmatch(token.strip())
    if not m:
        return None
    owner, repo, num = m.group("owner"), m.group("repo"), m.group("num")
    if owner:
        return f"{owner}/{repo}", num
    return REPO_ALIASES.get(repo or "", default_repo if not repo else f"xeprotocol/{repo}"), num


async def add_patch_ref(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    t: Ticket,
    *,
    repo: str,
    ref: str,
    kind: str = "pr",
    title: str = "",
    url: str = "",
    note: str = "",
    state: str = "",
    author: str = "",
) -> PatchRef | None:
    repo, ref = repo.strip(), str(ref).strip()
    if not repo or not ref or kind not in ("pr", "commit"):
        raise HTTPException(400, "repo, ref and kind (pr|commit) are required")
    url = url.strip()
    if url and not url.lower().startswith("https://"):
        # the page renders it as a link; nothing but https ever goes in an href here
        raise HTTPException(400, "a patch ref url must be https://")
    exists = (
        await db.execute(
            select(PatchRef).where(PatchRef.ticket_id == t.id, PatchRef.repo == repo, PatchRef.ref == ref)
        )
    ).scalar_one_or_none()
    if exists:
        changed = False
        for k, v in (("title", title), ("url", url), ("note", note), ("state", state), ("author", author)):
            if v and getattr(exists, k) != v:
                setattr(exists, k, v)
                changed = True
        return exists if changed else None
    if not url:
        url = f"https://github.com/{repo}/{'pull' if kind == 'pr' else 'commit'}/{ref}"
    pr = PatchRef(
        ticket_id=t.id,
        repo=repo,
        kind=kind,
        ref=ref,
        title=title[:512],
        url=url[:512],
        note=note[:128],
        state=state[:16],
        added_by=p.actor,
        author=author[:128],
    )
    db.add(pr)
    await db.flush()
    await ctx.events.append(
        db,
        "patch.linked",
        p.actor,
        {"ticket": t.id, "repo": repo, "kind": kind, "ref": ref, "note": note},
        ref=t.id,
        public=t.visibility == "public",
    )
    return pr


async def patch_ref(db: AsyncSession, t: Ticket, repo: str, ref: str) -> PatchRef:
    q = select(PatchRef).where(PatchRef.ticket_id == t.id, PatchRef.repo == repo, PatchRef.ref == ref)
    return (await db.execute(q)).scalar_one()


async def patches_for(db: AsyncSession, t: Ticket) -> list[PatchRef]:
    return list(
        (
            await db.execute(
                select(PatchRef).where(PatchRef.ticket_id == t.id).order_by(PatchRef.created_at.asc())
            )
        )
        .scalars()
        .all()
    )


def iso(dt) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None

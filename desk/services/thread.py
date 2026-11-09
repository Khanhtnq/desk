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
from .tickets import clean_text, utcnow

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


async def remove_message(
    db: AsyncSession, source: str, source_ref: str, *, mark: str = "[comment deleted at the source]"
) -> bool:
    """A comment deleted at the source (or taken off here) is marked, its body gone; the row stays so the
    thread's shape is honest about what was there (XE-1014)."""
    q = select(Message).where(Message.source == source, Message.source_ref == source_ref)
    m = (await db.execute(q)).scalar_one_or_none()
    if m is None:
        return False
    m.body, m.body_sealed = mark, None
    return True


async def add_note(
    ctx: Context, db: AsyncSession, p: Principal, t: Ticket, body: str, checked: dict | None = None
) -> Note:
    body = clean_text(body).strip()
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
    update: bool = False,
) -> Message | None:
    """Append to the public thread; idempotent on (source, source_ref). Private tickets seal the body.
    With `update`, an existing public row takes the new body (a comment edited at the source)."""
    if source_ref:
        exists = (
            await db.execute(
                select(Message).where(Message.source == source, Message.source_ref == source_ref)
            )
        ).scalar_one_or_none()
        if exists:
            if update and body is not None and t.visibility == "public" and not exists.body_sealed:
                new = clean_text(body)[:60_000]
                if new != exists.body:
                    exists.body = new  # an edited comment reads as edited here too (XE-1014)
                    return exists
            return None
    body = clean_text(body)[:60_000]
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
    body = clean_text(body).strip()
    if not body:
        raise HTTPException(400, "empty reply")
    if p.user is None:
        raise HTTPException(403, "only a person sends a public reply")
    # Mirrored when the source channel can carry it: a GitHub comment, a message in the Discord thread.
    # The worker handles GitHub; each bot handles its own channel.
    mirror = "queued" if t.source in ("github", "discord", "telegram") and t.visibility == "public" else "none"
    r = Reply(ticket_id=t.id, author_id=p.user.id, author_name=p.name, body=body, mirror=mirror)
    if t.visibility == "private":
        # the reply row follows the body into the vault, like the thread copy (XE-0426)
        if not ctx.vault.available:
            raise HTTPException(503, "the vault key is not loaded; replies on a private ticket wait")
        r.body, r.body_sealed = "", ctx.vault.seal_text(body)
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


def reply_body(ctx: Context, r: Reply) -> str:
    if r.body_sealed:
        try:
            return ctx.vault.open_text(r.body_sealed)
        except Exception:
            return "[sealed]"
    return r.body


async def replies_for(db: AsyncSession, t: Ticket) -> list[Reply]:
    return list(
        (await db.execute(select(Reply).where(Reply.ticket_id == t.id).order_by(Reply.created_at.asc())))
        .scalars()
        .all()
    )


UNNAMED_DUPLICATE = "an earlier report that is not public"


async def render_template(ctx: Context, db: AsyncSession, name: str, t: Ticket, **extra: str) -> str:
    """A reply template from the public register, with the ticket's facts filled in. The result is a draft
    in the editor, never a sent reply."""
    return await fill_for(ctx, db, ctx.config.reply_templates.get(name, ""), t, **extra)


async def fill_for(ctx: Context, db: AsyncSession, tpl: str, t: Ticket, **extra: str) -> str:
    """`fill`, with `{duplicate_url}` resolved for the text's audience. A reply on a public ticket is read
    by everyone; on a private one by its reporter, who may know their own tickets. A duplicate target the
    audience may not be told about (`tickets.hidden_targets`, XE-0799) is named as `UNNAMED_DUPLICATE`."""
    from ..authz import ANON
    from .tickets import hidden_targets, ticket_url

    if "duplicate_url" not in extra:
        url = UNNAMED_DUPLICATE
        if t.duplicate_of:
            audience = ANON
            if t.visibility == "private":
                audience = Principal(kind="reporter", reporter_id=t.reporter_id)
            if t.duplicate_of not in await hidden_targets(db, audience, [t]):
                url = ticket_url(ctx, t).rsplit("/", 1)[0] + "/" + t.duplicate_of
        extra["duplicate_url"] = url
    return fill(ctx, tpl, t, **extra)


def fill(ctx: Context, tpl: str, t: Ticket, **extra: str) -> str:
    """`{ticket_url}`, `{tier}` and the rest filled in from the ticket. Used for the public templates and
    for an agent's reply draft alike, so a draft can name the ticket without knowing its front door. Text
    that is not a template (a stray brace) comes back as it was. `{duplicate_url}` is filled only when
    given (see `fill_for`): without a reader in mind the desk does not know whether it may be named, and
    an unfilled placeholder keeps a draft in the editor (`review_reason`)."""
    from .tickets import assessment_held, ticket_url, xe_amount

    values = {
        "ticket_url": ticket_url(ctx, t),
        # where a reporter binds the address an award is paid to; same front door as the ticket
        "account_url": ticket_url(ctx, t).rsplit("/", 1)[0] + "/account",
        "award": "" if t.award_xe is None else xe_amount(t.award_xe),
        # the tier is held until the fix ships; a draft that names it early names nothing (XE-0733)
        "tier": "" if assessment_held(t) else ctx.config.tier_label(t.assessed_tier),
        "patch_refs": extra.pop("patch_refs", "the linked PR"),
        "what": extra.pop("what", "a reproduction"),
        "reason": extra.pop("reason", ""),
        "answer": extra.pop("answer", "(the answer goes here)"),
    }
    values.update(extra)
    return _fill_known(tpl, values)


_FIELD = re.compile(r"\{([a-z_]+)\}")


def _fill_known(tpl: str, values: dict[str, str]) -> str:
    """Only `{name}` placeholders the desk knows are filled, by plain substitution: no attribute or index
    access, no format specs, so a draft cannot reach into the ticket or the config (XE-0956). Anything
    else, braces included, stays as written."""
    return _FIELD.sub(lambda m: str(values[m.group(1)]) if m.group(1) in values else m.group(0), tpl)


PLAIN_LIMIT = 300
_URL = re.compile(r"https?://\S+")
_CODE = re.compile(r"`|\w+\(\)|\w+_\w+|\w+\.(go|py|js|ts|html|yaml|md)\b|\b\w+/\w+")
_TICKET_ID = re.compile(r"\b[A-Z]{2}-\d{4}\b")
_MONEY = re.compile(r"\b(award|awards|awarded|reward|bounty|pay|paid|payout|payment|xe)\b", re.I)
_CLOSING = re.compile(r"\b(clos(e|ed|ing)|invalid|out of scope|duplicate|not a bug|as designed)\b", re.I)
_PROMISE = re.compile(
    r"\b(within|by (monday|tuesday|wednesday|thursday|friday|saturday|sunday|next))\b", re.I
)


def review_reason(ctx: Context, text: str, t: Ticket) -> str | None:
    """Why a filled reply draft needs a person's read before it goes out, or None when it is a plain
    acknowledgement the desk can send as it stands. Plain means: short, names nothing but this ticket, no
    number (a tier, an amount, a date), no link but the ticket's own, no code or path, no word about
    money or closing, except inside the programme's stock lines (`plain_phrases` in the public copy).
    The rule is deliberately narrow; everything it does not recognise waits in the editor."""
    from .tickets import ticket_url

    body = (text or "").strip()
    if not body:
        return "empty"
    if len(body) > PLAIN_LIMIT:
        return f"over {PLAIN_LIMIT} characters"
    own = ticket_url(ctx, t)
    rest = body.replace(own, " ").replace(t.id, " ")
    # the programme's stock lines pass whatever words they carry; the rest of the text is still checked
    folded = re.sub(r"\s+", " ", rest)
    for phrase in ctx.config.plain_phrases:
        folded = re.sub(re.escape(re.sub(r"\s+", " ", phrase.strip())), " ", folded, flags=re.I)
    rest = folded
    if _URL.search(rest):
        return "has a link"
    if _TICKET_ID.search(rest):
        return "names another ticket"
    if "{" in rest or "}" in rest:
        return "has an unfilled placeholder"
    if re.search(r"\d", rest):
        return "has a number"
    if _CODE.search(rest):
        return "names code or a path"
    tiers = [k for k in ctx.config.tier_order if k != "none"] + [
        ctx.config.tier_label(k) for k in ctx.config.tier_order if k != "none"
    ]
    if re.search(r"\b(" + "|".join(re.escape(x) for x in tiers if x) + r"|tier)\b", rest, re.I):
        return "names a tier"
    if _MONEY.search(rest):
        return "mentions payment"
    if _CLOSING.search(rest):
        return "explains a closure"
    if _PROMISE.search(rest):
        return "promises a time"
    return None


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

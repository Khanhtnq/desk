"""GitHub <-> desk.

Inbound: issues become tickets (idempotent on repo+number), comments become public-thread messages,
PRs that reference an issue become patch refs, and a PR that says it fixes the issue (`fixes #n`) moves
the ticket: `fixing` while open, `patched` once merged. Runs as a full import, a `since` poll, or per
webhook delivery; all three go through the same `upsert_*` functions.

Outbound: the status label on the issue (the tool's labels only; anything else on the issue is left
alone), queued replies as comments, and close/reopen when the desk closes or reopens. A private
ticket being disclosed opens a new issue. GitHub is the mirror; the desk is the record.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import SYSTEM
from ..context import Context
from ..models import Note, PatchRef, Reply, Reporter, SyncCursor, Ticket
from . import github as gh
from . import thread
from . import tickets as tsvc
from .tickets import NewTicket, utcnow

log = logging.getLogger("desk.sync")
BOT_LOGINS = {"github-actions[bot]", "dependabot[bot]"}
DESK_MARK = "<!-- xe-desk -->"
# While the desk has not ruled, the GitHub issue is the reporter's draft and edits flow in. From `accepted`
# on, the desk's copy is what was assessed and stays as it was.
EDITABLE_STATUSES = ("new", "triaging", "needs-info")
BLOCKED_MARK = "[comment from a blocked account removed]"


def login_blocked(ctx: Context, login: str) -> bool:
    """An account on GITHUB_BLOCKED_LOGINS: its pull requests are not linked and its comments are not
    mirrored, so nothing it writes reaches a ticket page or a payout decision (XE-0128)."""
    return bool(login) and login.lower() in ctx.settings.blocked_logins


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


# ---- reporters --------------------------------------------------------------------------------------


async def reporter_for(db: AsyncSession, user: dict | None) -> Reporter | None:
    if not user or user.get("type") == "Bot":
        return None
    gid, login = user.get("id"), user.get("login") or ""
    r = None
    if gid is not None:
        r = (await db.execute(select(Reporter).where(Reporter.github_id == gid))).scalar_one_or_none()
    if r is None and login:
        r = (
            await db.execute(
                select(Reporter).where(Reporter.github_login == login, Reporter.github_id.is_(None))
            )
        ).scalar_one_or_none()
    if r is None:
        r = Reporter(github_login=login, github_id=gid, display_name=login)
        db.add(r)
        await db.flush()
    elif r.github_login != login or (r.github_id is None and gid is not None):
        r.github_login, r.github_id = login, gid
    return r


# ---- inbound ----------------------------------------------------------------------------------------


async def upsert_issue(
    ctx: Context, db: AsyncSession, repo: str, issue: dict, *, first_touch: bool = True
) -> tuple[Ticket, bool]:
    """Create or refresh the ticket for a GitHub issue. Returns (ticket, created). Only GitHub-owned
    facts are refreshed: title, body (while editable), github state and labels, source times."""
    number = str(issue["number"])
    t = await tsvc.find_by_source(db, "github", repo, number)
    body = issue.get("body") or ""
    title = (issue.get("title") or f"{repo}#{number}").strip()
    state = issue.get("state") or "open"
    labels = sorted(label["name"] for label in issue.get("labels") or [])
    created = False
    if t is None:
        reporter = await reporter_for(db, issue.get("user"))
        spec = NewTicket(
            kind="bounty",
            title=title,
            body=body,
            visibility="public",
            source="github",
            source_repo=repo,
            source_ref=number,
            source_url=issue.get("html_url") or "",
            reporter_id=reporter.id if reporter else None,
            claimed_tier=gh.claimed_tier(title, body),
            source_created_at=_dt(issue.get("created_at")),
            github_state=state,
        )
        # The worker polls the same repos; a CLI import running beside it can lose the race for an issue.
        # The unique index on the source is the referee: on a collision, take the other side's ticket.
        try:
            async with db.begin_nested():
                t = await tsvc.create(ctx, db, "desk", spec)
                t.github_labels = labels
            created = True
        except IntegrityError:
            t = await tsvc.find_by_source(db, "github", repo, number)
            if t is None:
                raise
            log.info("%s#%s was imported by another process meanwhile; using %s", repo, number, t.id)
        if created and first_touch and (ctx.config.desk.get("github") or {}).get("first_touch_note", True):
            await thread.add_note(ctx, db, SYSTEM, t, f"Imported from {repo}#{number}. First touch pending.")
    else:
        if (
            t.body_editable
            and t.visibility == "public"
            and t.status in EDITABLE_STATUSES
            and (t.title != title or t.body != body)
        ):
            # the issue is the reporter's draft until the desk rules on it; after that the record is fixed
            # and later edits on GitHub stay on GitHub. Every rewrite that does land is an event.
            pairs = (("title", t.title, title[:512]), ("body", t.body, body))
            changed = [k for k, a, b in pairs if a != b]
            t.title, t.body = title[:512], body
            await ctx.events.append(
                db, "ticket.edited", "desk", {"ticket": t.id, "fields": changed, "via": "github"}, ref=t.id
            )
        if t.github_state != state:
            t.github_state = state
            await ctx.events.append(db, "github.state", "desk", {"ticket": t.id, "state": state}, ref=t.id)
            if state == "closed" and t.is_open and t.status in ("new", "triaging", "needs-info"):
                # closed on GitHub by someone before the desk ruled; mirror it as stale so it is not lost
                await ctx.events.append(
                    db, "github.closed_externally", "desk", {"ticket": t.id, "status": t.status}, ref=t.id
                )
        if t.github_labels != labels:
            t.github_labels = labels
    return t, created


async def upsert_comment(
    ctx: Context, db: AsyncSession, t: Ticket, comment: dict, *, update: bool = False
) -> bool:
    user = comment.get("user") or {}
    login = user.get("login") or ""
    body = comment.get("body") or ""
    if login_blocked(ctx, login):
        # not mirrored; a copy taken before the block is emptied rather than left to stand
        await thread.remove_message(db, "github", str(comment["id"]), mark=BLOCKED_MARK)
        return False
    # team authorship is the bot account and nothing else; the marker is a public string anyone can type,
    # so it only ever strips, never vouches
    is_team = bool(ctx.settings.github_bot_login) and login == ctx.settings.github_bot_login
    m = await thread.add_message(
        ctx,
        db,
        t,
        source="github",
        source_ref=str(comment["id"]),
        author=login,
        body=body.replace(DESK_MARK, "").strip(),
        created_at=_dt(comment.get("created_at")),
        is_team=is_team,
        update=update,
    )
    wrote = _dt(comment.get("created_at"))
    if wrote is not None and await comment_is_teams(ctx, db, t, comment):
        # told from when it was said: a comment from before a status move leaves the move untold
        thread.mark_told(t, wrote)
    return m is not None


async def comment_is_teams(ctx: Context, db: AsyncSession, t: Ticket, comment: dict) -> bool:
    """Is this comment the team writing to the reporter? GitHub's word for who maintains the repo, as
    for a PR (`pull_is_maintainers`), or the desk's own bot; never the ticket's own reporter, so a team
    member who filed the report is not told by their own follow-up. It decides `told_at` and nothing
    else: the team badge on a thread message stays the bot's alone (XE-0200)."""
    user = comment.get("user") or {}
    login = user.get("login") or ""
    bot = ctx.settings.github_bot_login
    maintainer = (comment.get("author_association") or "").upper() in MAINTAINER_ASSOCIATIONS
    if not login or not (maintainer or (bool(bot) and login == bot)):
        return False
    if t.reporter_id:
        r = (await db.execute(select(Reporter).where(Reporter.id == t.reporter_id))).scalar_one_or_none()
        if r is not None and (
            (r.github_login or "").lower() == login.lower()
            or (r.github_id is not None and r.github_id == user.get("id"))
        ):
            return False
    return True


# Anyone can open a PR against a public repo, so a PR's *existence* proves nothing; only a maintainer's
# word (or a merge, which needs write access) may move a ticket. GitHub's author_association names the
# relationship; the desk's own bot account counts too.
MAINTAINER_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})


def pull_is_maintainers(ctx: Context, pull: dict) -> bool:
    login = (pull.get("user") or {}).get("login") or ""
    bot = ctx.settings.github_bot_login
    if (pull.get("author_association") or "").upper() in MAINTAINER_ASSOCIATIONS:
        return True
    return bool(bot) and login == bot


async def link_pull(ctx: Context, db: AsyncSession, repo: str, pull: dict) -> int:
    """Attach a PR to every ticket whose issue it references, and let a PR that says it fixes the issue
    move the ticket: `fixing` while a maintainer's PR is open, `patched` once any PR is merged, and back
    to where it was if the PR that moved it is closed unmerged with nothing else open against the ticket.
    A stranger's fork PR links but moves nothing until it is merged. A bare `#n` mention links only.
    Returns how many links were new."""
    text = f"{pull.get('title') or ''}\n{pull.get('body') or ''}"
    refs = gh.issue_refs(text)
    if not refs:
        return 0
    fixes = gh.closing_refs(text)
    state = "merged" if pull.get("merged_at") else (pull.get("state") or "open")
    author = (pull.get("user") or {}).get("login") or ""
    if login_blocked(ctx, author):
        # the PR is not linked, and a link made before the block comes off; a ref that moved a ticket
        # (only ever a maintainer's) is left so the return hop still has its record
        await db.execute(
            delete(PatchRef).where(
                PatchRef.repo == repo,
                PatchRef.ref == str(pull["number"]),
                PatchRef.kind == "pr",
                PatchRef.moved_from == "",
            )
        )
        return 0
    trusted = pull_is_maintainers(ctx, pull)
    n = 0
    for issue_no in refs:
        t = await tsvc.find_by_source(db, "github", repo, str(issue_no))
        if t is None:
            continue
        if issue_no in fixes and (state != "open" or trusted):
            q = select(PatchRef.followed).where(
                PatchRef.ticket_id == t.id, PatchRef.repo == repo, PatchRef.ref == str(pull["number"])
            )
            if (await db.execute(q)).scalar_one_or_none() != state:
                # this PR may be about to move the ticket: the row lock first, before the link is
                # logged (the order every writer takes them in), and so that the follower reads the
                # status as it is now and not as this pass loaded it
                await tsvc.lock(db, t)
        pr = await thread.add_patch_ref(
            ctx,
            db,
            SYSTEM,
            t,
            repo=repo,
            ref=str(pull["number"]),
            kind="pr",
            title=pull.get("title") or "",
            url=pull.get("html_url") or "",
            state=state,
            author=author,
        )
        if pr is not None:
            n += 1
        if issue_no in fixes:
            row = pr or await thread.patch_ref(db, t, repo, str(pull["number"]))
            await _follow_pull_state(ctx, db, t, row, state, trusted=trusted)
    return n


# A fixing PR drives the public ticket the way the internal tracker does. Only forward along the
# allowed path, only from statuses before `patched`, and never past it: what happens after a fix ships
# (disclosure, award, payment) is a person's call. Every change is SYSTEM with via="github:<repo>#<pr>".
#
# Both followers act on a change at the source, once (XE-2080): a PR opened, merged or closed, a tracker
# issue opened or closed. The state last acted on is kept (`PatchRef.followed`,
# `Ticket.internal_followed`), and the same PR or issue read again in that state moves nothing, so what
# a person sets afterwards (a walk back from `patched` to `fixing`, say) stands until the source itself
# changes. Without it every redelivery, edit or re-import of a merged PR patched the ticket again.
PRE_PATCH = ("new", "triaging", "needs-info", "accepted", "fixing")


async def _follow_pull_state(
    ctx: Context, db: AsyncSession, t: Ticket, pr: PatchRef, state: str, *, trusted: bool
) -> bool:
    if t.kind != "bounty" or pr.followed == state:
        return False  # a question is not followed, and nothing is recorded against the day it is a report
    if state == "open" and not trusted:
        return False  # not this PR's say; unrecorded, so it has it if its author is a maintainer later
    # decided on the rows as they are now. A poll is one session that keeps what it loaded: the ticket
    # read in its first phase is stale by the time the pulls are read, and a move decided on the stale
    # status was refused by `set_status` (which does re-read) after the change had been recorded as
    # acted on, so it was never acted on at all (XE-2080 sweep)
    await tsvc.lock(db, t)
    await db.refresh(pr)
    if pr.followed == state:
        return False
    pr.followed = state
    if t.status not in PRE_PATCH:
        return False
    via = f"github:{pr.repo}#{pr.ref}"
    ref = f"{pr.repo.split('/')[-1]}#{pr.ref}"
    if state == "merged":
        target, reason = "patched", f"{ref} merged"  # a merge is a maintainer's act whoever wrote the PR
    elif state == "open":
        if t.status == "fixing":
            if not pr.moved_from:
                # a second maintainer PR while fixing: it inherits where the ticket came from, so its
                # close returns the ticket there and not to a guessed status (XE-0634)
                pr.moved_from = await _moved_from(db, t)
            return False
        target, reason = "fixing", f"{ref} opened"
    else:  # closed without merging: only the PR that moved the ticket (or a maintainer's) moves it back
        if t.status != "fixing" or not (trusted or pr.moved_from):
            return False
        if await _other_live_patches(ctx, db, t, pr.repo, pr.ref):
            return False
        # where the ticket was before any maintainer PR moved it; this PR's own record first (XE-0634)
        target = pr.moved_from or await _moved_from(db, t) or "accepted"
        reason = f"{ref} closed unmerged"
        if target == "new":
            target = "triaging"  # nothing goes back to new; the PR was read, so someone has looked
    if tsvc.status_path(t.kind, t.status, target) is None:
        return False
    before = t.status
    await tsvc.set_status_via_path(ctx, db, SYSTEM, t, target, reason=reason, via=via)
    if target == "fixing" and not pr.moved_from:
        pr.moved_from = before
    return True


async def _moved_from(db: AsyncSession, t: Ticket) -> str:
    q = (
        select(PatchRef.moved_from)
        .where(PatchRef.ticket_id == t.id, PatchRef.kind == "pr", PatchRef.moved_from != "")
        .order_by(PatchRef.id)
    )
    return (await db.execute(q)).scalars().first() or ""


async def _other_live_patches(ctx: Context, db: AsyncSession, t: Ticket, repo: str, ref: str) -> bool:
    """Is any other PR against this ticket still open or merged, from someone whose PR counts? A
    stranger's open PR holds nothing (XE-0634): only a maintainer's, or one that moved the ticket."""
    q = select(PatchRef).where(
        PatchRef.ticket_id == t.id,
        PatchRef.kind == "pr",
        PatchRef.state.in_(("open", "merged")),
        ~((PatchRef.repo == repo) & (PatchRef.ref == ref)),
    )
    bot = ctx.settings.github_bot_login
    for other in (await db.execute(q)).scalars().all():
        if other.state == "merged" or other.moved_from or (bot and other.author == bot):
            return True
    return False


async def import_repo(
    ctx: Context,
    db: AsyncSession,
    client: gh.GitHub,
    repo: str,
    *,
    since: str | None = None,
    comments: bool = True,
    pulls: bool = True,
) -> dict:
    """Full or incremental import of one repository. Commits as it goes so a long run is resumable."""
    stats = {"repo": repo, "issues": 0, "created": 0, "comments": 0, "pulls": 0}
    newest = since or ""
    async for issue in client.issues(repo, since=since):
        t, created = await upsert_issue(ctx, db, repo, issue)
        stats["issues"] += 1
        stats["created"] += int(created)
        if comments and (issue.get("comments") or 0) > 0:
            async for c in client.comments(repo, issue["number"], since=since):
                stats["comments"] += int(await upsert_comment(ctx, db, t, c))
        newest = max(newest, issue.get("updated_at") or "")
        await db.commit()
    if pulls:
        async for pull in client.pulls(repo):
            if since and (pull.get("updated_at") or "") < since:
                continue
            stats["pulls"] += await link_pull(ctx, db, repo, pull)
        await db.commit()
    await set_cursor(db, f"github:{repo}:issues", newest, stats)
    await db.commit()
    return stats


async def poll(ctx: Context, db: AsyncSession, client: gh.GitHub) -> list[dict]:
    out = []
    for repo in ctx.config.repos:
        # one repo's bad day does not stop the others or the tracker being read (XE-1160)
        try:
            async with db.begin_nested():
                since = await get_cursor(db, f"github:{repo}:issues")
                out.append(await import_repo(ctx, db, client, repo, since=since or None))
        except Exception as e:
            log.exception("poll of %s failed: %s", repo, e)
            out.append({"repo": repo, "error": str(e)[:200]})
    if ctx.config.internal_repo:
        since = await get_cursor(db, f"github:{ctx.config.internal_repo}:issues")
        out.append(await import_internal(ctx, db, client, since=since or None))
    return out


# ---- the engineering tracker (read-only) ------------------------------------------------------------
#
# The engineering tickets live in a private repo and name the public reports they cover: "security: bounty
# bundle xe#8". The desk never writes there. It reads the tag to fill `internal_ref`, and reads the
# issue's state to move the public ticket: open → accepted; closed as completed → patched, which puts
# the ticket in the outbox for a human to tell the reporter; closed as not planned → a note, since the
# public verdict is the Reviewer's call. Every change is the SYSTEM principal with via="internal".


async def link_internal_issue(ctx: Context, db: AsyncSession, issue: dict) -> dict:
    """Apply one internal issue to every public ticket it names. Idempotent."""
    repo = ctx.config.internal_repo
    number = int(issue["number"])
    ref = f"#{number}"
    via = f"internal:{repo}{ref}"
    text = f"{issue.get('title') or ''}\n{issue.get('body') or ''}"
    stats = {"issue": number, "tagged": 0, "linked": 0, "moved": 0, "noted": 0}
    for t in await _tagged_tickets(ctx, db, text, ref):
        stats["tagged"] += 1
        if not t.internal_ref and t.internal_followed.startswith(f"{ref}:"):
            # it was linked to this issue and followed it, and a person has since cleared the link (the
            # wrong class, say). That stands: the issue still naming the report does not put it back
            cleared = f"Internal ticket {ref} names this report; its link here was cleared by hand."
            stats["noted"] += int(await _note_once(ctx, db, t, cleared))
            continue
        if not t.internal_ref:
            await tsvc.set_facts(ctx, db, SYSTEM, t, {"internal_ref": ref}, via=via)
            stats["linked"] += 1
        elif t.internal_ref != ref:
            # the triage doc or a human already named another ticket; say so once rather than overwrite
            if await _note_once(ctx, db, t, f"Internal ticket {ref} also names this report ({repo})."):
                stats["noted"] += 1
            continue
        try:
            stats["moved"] += int(await _follow_internal_state(ctx, db, t, issue, via))
        except HTTPException as e:
            # a ticket the tracker cannot move (closed, paid, a kind that has no such path): note it, go on
            log.warning("internal %s cannot move %s: %s", ref, t.id, e.detail)
            stats["noted"] += int(await _note_once(ctx, db, t, f"Internal ticket {ref} changed; {e.detail}."))
    return stats


async def _tagged_tickets(ctx: Context, db: AsyncSession, text: str, ref: str = "") -> list[Ticket]:
    """The desk tickets an internal issue applies to: GitHub-sourced ones it names by `xe#8`, any ticket it
    names by desk id `XE-0232`, and every ticket already carrying it as `internal_ref`. The last keeps a
    report following the engineering ticket after its body is edited and the mention drops out; a link
    once made is not undone by a rewrite. One ticket reached several ways is one ticket."""
    out: list[Ticket] = []
    for pub_repo, pub_num in gh.public_tags(text, ctx.config.internal_aliases):
        t = await tsvc.find_by_source(db, "github", pub_repo, str(pub_num))
        if t is not None and t not in out:
            out.append(t)
    for tid in gh.desk_tags(text):
        t = await tsvc.get(db, tid)
        if t is not None and t not in out:
            out.append(t)
    if ref:
        q = select(Ticket).where(Ticket.internal_ref == ref).order_by(Ticket.id)
        for t in (await db.execute(q)).scalars().all():
            if t not in out:
                out.append(t)
    return out


async def _follow_internal_state(ctx: Context, db: AsyncSession, t: Ticket, issue: dict, via: str) -> bool:
    if t.kind != "bounty":
        return False
    state = issue.get("state") or "open"
    reason = issue.get("state_reason") or ""
    ref = f"#{issue['number']}"
    seen = f"{ref}:{state}:{reason}"[:64]
    if t.internal_followed == seen:
        return False  # read again, unchanged: it has had its say (see PRE_PATCH above)
    await tsvc.lock(db, t)  # and the status below is the one in the database now, as for a PR
    if t.internal_followed == seen or t.internal_ref != ref:
        return False
    t.internal_followed = seen
    if state == "open":
        if t.status in ("new", "triaging", "needs-info"):
            await _accept(ctx, db, t, f"internal {ref} open", via)
            return True
        return False
    if reason not in ("", "completed"):
        # only a close that says the work was done is a fix. `not_planned`, `duplicate` and whatever
        # GitHub adds next are a note: patched puts the report in the outbox, and the reporter is told
        # it was fixed fifteen minutes later
        why = reason.replace("_", " ")[:32]
        return await _note_once(
            ctx, db, t, f"Internal ticket {ref} was closed as {why}; the public verdict is yours."
        )
    if t.status in ("accepted", "fixing"):
        await tsvc.set_status(ctx, db, SYSTEM, t, "patched", reason=f"internal {ref} closed", via=via)
        return True
    if t.status in ("new", "triaging", "needs-info"):
        # fixed before the desk ever ruled: accept, then patch, so the history reads honestly
        await _accept(ctx, db, t, f"internal {ref} closed", via)
        await tsvc.set_status(ctx, db, SYSTEM, t, "patched", reason=f"internal {ref} closed", via=via)
        return True
    return False


async def _accept(ctx: Context, db: AsyncSession, t: Ticket, reason: str, via: str) -> None:
    """Accept along the allowed path. A `new` ticket passes through `triaging` first, as a person would
    have to; the tracker naming it is the triage."""
    if t.status == "new":
        await tsvc.set_status(ctx, db, SYSTEM, t, "triaging", reason=reason, via=via)
    await tsvc.set_status(ctx, db, SYSTEM, t, "accepted", reason=reason, via=via)


async def _note_once(ctx: Context, db: AsyncSession, t: Ticket, body: str) -> bool:
    q = select(Note.id).where(Note.ticket_id == t.id, Note.author == SYSTEM.actor, Note.body == body)
    if (await db.execute(q)).first():
        return False
    await thread.add_note(ctx, db, SYSTEM, t, body)
    return True


async def import_internal(
    ctx: Context, db: AsyncSession, client: gh.GitHub, *, since: str | None = None
) -> dict:
    """Read the tracker, newest-updated last, and apply each issue. Commits as it goes."""
    repo = ctx.config.internal_repo
    stats = {"repo": repo, "issues": 0, "comments": 0, "pulls": 0, "tagged": 0, "linked": 0, "moved": 0}
    if not repo:
        return stats
    newest = since or ""
    async for issue in client.issues(repo, since=since):
        s = await link_internal_issue(ctx, db, issue)
        stats["issues"] += 1
        for k in ("tagged", "linked", "moved"):
            stats[k] += s[k]
        newest = max(newest, issue.get("updated_at") or "")
        await db.commit()
    await set_cursor(db, f"github:{repo}:issues", newest, stats)
    await db.commit()
    return stats


async def handle_webhook(ctx: Context, db: AsyncSession, event: str, payload: dict) -> dict:
    repo = (payload.get("repository") or {}).get("full_name") or ""
    if repo and repo == ctx.config.internal_repo:
        if event == "issues" and "issue" in payload and "pull_request" not in payload["issue"]:
            return {"internal": await link_internal_issue(ctx, db, payload["issue"])}
        return {"ignored": "internal event"}
    if repo not in ctx.config.repos:
        return {"ignored": "repo"}
    action = payload.get("action") or ""
    if event == "issues" and "issue" in payload:
        t, created = await upsert_issue(ctx, db, repo, payload["issue"])
        return {"ticket": t.id, "created": created, "action": action}
    if event == "issue_comment" and "issue" in payload and "comment" in payload:
        if "pull_request" in payload["issue"]:
            return {"ignored": "pr comment"}
        t, _ = await upsert_issue(ctx, db, repo, payload["issue"])
        if action in ("created", "edited"):
            added = await upsert_comment(ctx, db, t, payload["comment"], update=action == "edited")
            return {"ticket": t.id, "comment": added}
        if action == "deleted":
            gone = await thread.remove_message(db, "github", str(payload["comment"].get("id") or ""))
            return {"ticket": t.id, "action": action, "removed": gone}
        return {"ticket": t.id, "action": action}
    if event == "pull_request" and "pull_request" in payload:
        n = await link_pull(ctx, db, repo, payload["pull_request"])
        return {"linked": n}
    return {"ignored": event}


# ---- cursors ----------------------------------------------------------------------------------------


async def get_cursor(db: AsyncSession, key: str) -> str:
    row = (await db.execute(select(SyncCursor).where(SyncCursor.key == key))).scalar_one_or_none()
    return row.value if row else ""


async def set_cursor(db: AsyncSession, key: str, value: str, detail: dict | None = None) -> None:
    row = (await db.execute(select(SyncCursor).where(SyncCursor.key == key))).scalar_one_or_none()
    if row is None:
        row = SyncCursor(key=key)
        db.add(row)
    row.value = value
    row.detail = detail or {}


# ---- outbound ---------------------------------------------------------------------------------------


def _footer(ctx: Context, t: Ticket) -> str:
    return f"\n\n{DESK_MARK}\n<sub>{t.id} · {tsvc.ticket_url(ctx, t)}</sub>"


def writes_to_issue(t: Ticket) -> bool:
    """The desk writes to a ticket's GitHub issue only while the ticket is public (XE-0299, XE-0700).
    A report the team sealed keeps its issue, which was public before the desk saw it; what the desk
    then decides about it (accepted, fixing, patched, closed and why, what it tells the reporter) is the
    sealed part, and a label or a closed issue would publish it. Every function below that writes to
    GitHub about a ticket asks this first; the selectors that feed them only save the work."""
    return t.source == "github" and bool(t.source_repo) and t.visibility == "public"


async def push_labels(ctx: Context, db: AsyncSession, client: gh.GitHub, t: Ticket) -> bool:
    """Make the issue's status label match the ticket. Other labels are left as they are."""
    if not client.enabled:
        return False
    await tsvc.as_it_is_now(db, t)
    if not writes_to_issue(t):
        return False
    cfg = ctx.config
    want = cfg.label_for(t.status, t.closed_reason)
    ours = cfg.tool_label_names
    keep = [name for name in (t.github_labels or []) if name not in ours]
    if want:
        keep.append(want["name"])
    if sorted(keep) == sorted(t.github_labels or []):
        return False
    names = await client.set_labels(t.source_repo, int(t.source_ref), keep)
    t.github_labels = sorted(names)
    await ctx.events.append(
        db, "github.labels", "desk", {"ticket": t.id, "labels": t.github_labels}, ref=t.id
    )
    return True


async def push_state(ctx: Context, db: AsyncSession, client: gh.GitHub, t: Ticket) -> bool:
    """Close the issue when the desk closes the ticket; reopen when the desk reopens it."""
    if not client.enabled:
        return False
    await tsvc.as_it_is_now(db, t)
    if not writes_to_issue(t):
        return False
    want = "closed" if t.status in ("closed", "paid") else "open"
    if t.github_state == want:
        return False
    reason = None
    if want == "closed":
        reason = (
            "not_planned"
            if t.closed_reason in ("invalid", "out-of-scope", "duplicate", "stale", "withdrawn")
            else "completed"
        )
    await client.set_state(t.source_repo, int(t.source_ref), want, reason)
    t.github_state = want
    await ctx.events.append(
        db, "github.state_pushed", "desk", {"ticket": t.id, "state": want, "reason": reason}, ref=t.id
    )
    return True


async def mirror_reply(ctx: Context, db: AsyncSession, client: gh.GitHub, r: Reply) -> bool:
    t = await tsvc.get(db, r.ticket_id)
    if t is not None:
        await tsvc.as_it_is_now(db, t, r)  # the seal that made the ticket private also took the reply back
    if r.mirror != "queued":
        return False
    if t is None or not writes_to_issue(t):
        # a ticket made private after the reply was queued keeps the reply at home
        r.mirror = "none"
        return False
    if not client.enabled:
        r.mirror_error = "github token not configured"
        return False
    try:
        c = await client.comment(t.source_repo, int(t.source_ref), r.body + _footer(ctx, t))
    except gh.GitHubError as e:
        r.mirror = "failed"
        r.mirror_error = str(e)[:2000]
        await ctx.events.append(
            db,
            "reply.mirror_failed",
            "desk",
            {"ticket": t.id, "reply": r.id, "error": str(e)[:200]},
            ref=t.id,
        )
        return False
    r.mirror, r.mirror_ref, r.mirror_error, r.sent_at = "sent", c.get("html_url") or "", "", utcnow()
    await thread.reply_carried(
        ctx, db, t, r, source="github", source_ref=str(c["id"]), created_at=_dt(c.get("created_at"))
    )
    await ctx.events.append(
        db, "reply.mirrored", "desk", {"ticket": t.id, "reply": r.id, "url": r.mirror_ref}, ref=t.id
    )
    return True


async def queued_replies(db: AsyncSession, limit: int = 50) -> list[Reply]:
    """Replies for the worker to mirror. Chat-sourced tickets are left queued for their bot."""
    q = (
        select(Reply)
        .join(Ticket, Ticket.id == Reply.ticket_id)
        .where(Reply.mirror == "queued", Ticket.source.notin_(("discord", "telegram")))
        .order_by(Reply.created_at.asc())
        .limit(limit)
    )
    return list((await db.execute(q)).scalars().all())


async def open_disclosure(ctx: Context, db: AsyncSession, client: gh.GitHub, t: Ticket) -> str:
    """A disclosed private ticket gets a public issue in the primary repo and becomes a GitHub-sourced
    ticket from then on, so labels and replies flow like any other. Only while it is public: one sealed
    again after its disclosure and before the worker came round gets no issue (the same rule as
    `writes_to_issue`, for the issue that does not exist yet)."""
    if not client.enabled:
        return ""
    await tsvc.as_it_is_now(db, t)
    if t.source == "github" or t.visibility != "public":
        return ""
    repo = ctx.config.primary_repo
    patches = await thread.patches_for(db, t)
    lines = [
        t.body or "",
        "",
        "---",
        f"Disclosed from the desk as {t.id}; reported privately on "
        f"{t.source_created_at.date().isoformat() if t.source_created_at else t.created_at.date().isoformat()}.",
    ]
    if patches:
        lines.append(
            "Fixed in "
            + ", ".join(f"{p.repo}#{p.ref}" if p.kind == "pr" else f"{p.repo}@{p.ref[:10]}" for p in patches)
            + "."
        )
    label = ctx.config.label_for(t.status, t.closed_reason)
    issue = await client.create_issue(
        repo, t.title, "\n".join(lines) + _footer(ctx, t), [label["name"]] if label else []
    )
    t.source, t.source_repo, t.source_ref = "github", repo, str(issue["number"])
    t.source_url, t.github_state = issue.get("html_url") or "", "open"
    t.github_labels = sorted(label["name"] for label in issue.get("labels") or [])
    t.body_editable = False
    await ctx.events.append(
        db, "github.disclosed", "desk", {"ticket": t.id, "issue": f"{repo}#{issue['number']}"}, ref=t.id
    )
    return t.source_url


async def tickets_needing_push(db: AsyncSession) -> list[Ticket]:
    """GitHub-sourced public tickets whose status label or state may differ from the issue. Cheap filter
    here; push_* compare properly, and ask `writes_to_issue` themselves."""
    q = select(Ticket).where(
        Ticket.source == "github", Ticket.status != "new", Ticket.visibility == "public"
    )
    return list((await db.execute(q)).scalars().all())

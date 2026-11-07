"""Server-rendered pages. One app behind two front doors: the bounty host and the support host show
the same templates with the kind preselected. Writes happen from the pages' small scripts through the
JSON API with the session cookie and CSRF header, never through forms."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from markupsafe import Markup, escape
from sqlalchemy import select

from . import __version__, brand
from .auth import resolve, safe_next
from .authz import ANON, Principal, can
from .brief import build_agent_brief, fix_brief
from .context import get_context
from .db import session
from .api.public import log_scope
from .log import EventLog, event_to_dict, is_admin_kind
from .mirror import build_llms_txt, md_path
from .models import Reporter
from .services import proposals as psvc
from .services import reporters as rsvc
from .services import thread, users
from .services import tickets as tsvc
from .services.tickets import Filters

router = APIRouter(include_in_schema=False)
TICKET_ID = re.compile(r"X[ES]-\d{4,}", re.IGNORECASE)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

_md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")
# notes are often typed as plain text with single line breaks; keep those breaks
_md_notes = MarkdownIt("commonmark", {"html": False, "linkify": False, "breaks": True}).enable("table")


def _fmt_ns(ns: int | None) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ns else ""


def _fmt_dt(dt: datetime | None, with_time: bool = True) -> str:
    if not dt:
        return ""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC" if with_time else "%Y-%m-%d")


def _short(h: str | None, n: int = 10) -> str:
    return (h[:n] + "…") if h and len(h) > n else (h or "")


def _xe(micro) -> str:
    if micro is None:
        return "—"
    whole, frac = divmod(int(micro), 1_000_000)
    return f"{whole:,}" if frac == 0 else f"{whole:,}.{str(frac).rstrip('0')}"


def _render_md(text: str | None) -> Markup:
    """Reporter text rendered with HTML disabled; links are rel=nofollow via a post-pass."""
    html = _md.render(text or "")
    return Markup(html.replace("<a href=", '<a rel="nofollow noopener" target="_blank" href='))


templates.env.filters["ns"] = _fmt_ns
templates.env.filters["dt"] = _fmt_dt
templates.env.filters["day"] = lambda d: _fmt_dt(d, False)
templates.env.filters["short"] = _short
templates.env.filters["xe"] = _xe
templates.env.filters["md"] = _render_md
templates.env.filters["md_note"] = lambda text: Markup(
    _md_notes.render(text or "").replace("<a href=", '<a rel="nofollow noopener" target="_blank" href=')
)
templates.env.filters["md_path"] = md_path


def _asset_version() -> str:
    """A short hash of the static files, so a deploy never serves a page against a cached script."""
    import hashlib

    h = hashlib.sha256()
    for f in sorted((Path(__file__).parent / "static").glob("*")):
        if f.is_file():
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()[:10]


ASSET_V = _asset_version()
templates.env.globals["asset"] = lambda path: f"{path}?v={ASSET_V}"
templates.env.globals["brand"] = brand
templates.env.globals["held"] = tsvc.assessment_held  # the assessment is published from patched on
templates.env.filters["esc"] = escape


def site_for(request: Request) -> str:
    host = request.headers.get("host", "").split(":")[0].lower()
    s = get_context().settings
    return (
        "support" if host and host == s.support_host.lower() and s.support_host != s.bounty_host else "bounty"
    )


def site_url(c, site: str) -> str:
    return f"{c.settings.scheme}://{c.settings.hosts[site]}"


def other_site(request: Request, site: str, path: str) -> RedirectResponse | None:
    """A page that belongs to the other front door redirects there, when the doors are separate hosts."""
    c = get_context()
    if site_for(request) == site or c.settings.hosts["bounty"] == c.settings.hosts["support"]:
        return None
    return RedirectResponse(f"{site_url(c, site)}{path}", status_code=302)


async def principal(db, request: Request) -> tuple[Principal, str]:
    """Who is looking, and their CSRF token. The reporter (if any) is left on request.state for render()."""
    try:
        a = await resolve(db, request)
    except Exception:
        request.state.reporter = None
        return ANON, ""
    request.state.reporter = a.reporter
    return a.principal, a.csrf


# Which social card a page gets. Anything not listed, and every team page, gets the site card.
OG_PAGES = {"/": "index", "/scope": "scope", "/leaderboard": "leaderboard", "/log": "log", "/agent": "agent"}
OG_PAGES |= {"/report": "report", "/ask": "ask", "/live": "live"}


def og_default(c, request: Request, site: str, copy: dict) -> dict:
    """The og:* set for a page: absolute URLs, since crawlers fetch the image without a base."""
    base = site_url(c, site)
    sc = (copy.get("support") or {}) if site == "support" else copy
    name = copy.get("support_name" if site == "support" else "bounty_name", copy.get("site_name"))
    slug = OG_PAGES.get(request.url.path, "index")
    card = ((sc.get("cards") or {}).get(slug) or {}) if slug != "index" else {}
    return {
        "title": card.get("title") or name,
        "description": card.get("line") or sc.get("footer_line", ""),
        "image": f"{base}/og/page/{slug}.png?v={c.config.hashes.get('copy/public.yaml', '')[:10]}",
        "url": f"{base}{request.url.path}",
        "site_name": name,
    }


def render(request: Request, name: str, ctx: dict, status_code: int = 200) -> HTMLResponse:
    c = get_context()
    p: Principal = ctx.get("p") or ANON
    site = site_for(request)
    copy = c.config.copy_public
    og = og_default(c, request, site, copy)
    if "og" in ctx:
        og = {**og, **ctx.pop("og")}
    base = {
        "og": og,
        "request": request,
        "copy": copy,
        "cfg": c.config,
        "badge": c.node.badge,
        "network_id": c.node.network_id,
        "version": __version__,
        "hosts": c.settings.hosts,
        "scheme": c.settings.scheme,
        "site": site,
        "site_name": copy.get("support_name" if site == "support" else "bounty_name", copy.get("site_name")),
        "site_copy": copy.get("support") or {} if site == "support" else copy,
        "bounty_url": site_url(c, "bounty"),
        "support_url": site_url(c, "support"),
        "split": c.settings.hosts["bounty"] != c.settings.hosts["support"],
        "me": getattr(request.state, "reporter", None),
        "github_sign_in": bool(c.settings.github_oauth_client_id),
        "discord_sign_in": c.settings.discord_sign_in,
        "mail_sign_in": bool(c.settings.smtp_host),
        "p": p,
        "team": p.is_team,
        "csrf": ctx.get("csrf", ""),
        "can_tier": can(p, "tier"),
        "can_award": can(p, "award"),
        "is_admin": can(p, "admin"),
        "path": request.url.path,
    }
    return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status_code)


@router.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt(request: Request):
    c = get_context()
    site = site_for(request)
    return PlainTextResponse(
        build_llms_txt(
            c.config, site_url(c, site), c.node.network_id, site=site, other=site_url(c, "bounty")
        ),
        media_type="text/plain; charset=utf-8",
    )


# ---- lists ------------------------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def home(
    request: Request,
    status: str | None = None,
    area: str | None = None,
    gate: str | None = None,
    tier: str | None = None,
    verdict: str | None = None,
    pending: bool | None = None,
    q: str | None = None,
    sort: str | None = None,
):
    c = get_context()
    # The front door decides: bounty reports on one host, support questions on the other. The bounty
    # opens on open reports by severity; support opens on everything by last update, since an answered
    # question is the point of the page, not something to hide behind a filter.
    kind = site_for(request)
    status = status or ("all" if kind == "support" else "open")
    sort = sort or ("updated" if kind == "support" else "severity")
    async with session() as db:
        p, csrf = await principal(db, request)
        f = Filters(
            kind=kind,
            status=status,
            area=area,
            gate=gate,
            tier=tier,
            verdict=verdict,
            pending=pending,
            q=q,
            sort=sort,
            limit=300,
        )
        rows = await tsvc.list_tickets(db, c.config, p, f)
        ids = [t.id for t in rows]
        prs = await tsvc.patch_counts(db, ids)
        pend = await tsvc.pending_counts(db, ids) if p.is_team else {}
        counts = await tsvc.counts(db, p, kind)
        head = await EventLog.head(db)
    return render(
        request,
        "support_list.html" if kind == "support" else "list.html",
        {
            "p": p,
            "csrf": csrf,
            "tickets": rows,
            "prs": prs,
            "pend": pend,
            "counts": counts,
            "f": f,
            "kind": kind,
            "head": head,
        },
    )


@router.get("/bounty", response_class=HTMLResponse)
async def bounty_list(request: Request):
    return other_site(request, "bounty", "/") or RedirectResponse("/", status_code=302)


@router.get("/support", response_class=HTMLResponse)
async def support_list(request: Request):
    return other_site(request, "support", "/") or RedirectResponse("/", status_code=302)


# ---- a ticket ---------------------------------------------------------------------------------------


@router.get("/bounty/{tid}", include_in_schema=False)
@router.get("/support/{tid}", include_in_schema=False)
async def ticket_page_old_path(request: Request, tid: str):
    """The original URL shape, kept forever: links to it are in GitHub threads and chat."""
    c = get_context()
    async with session() as db:
        p, _ = await principal(db, request)
        t = await tsvc.get_for(db, p, tid)
    return RedirectResponse(tsvc.ticket_url(c, t), status_code=301)


# ---- public pages -----------------------------------------------------------------------------------


@router.get("/agent", response_class=HTMLResponse)
async def agent_page(request: Request):
    """The agent brief as a page, for the person writing the prompt. The authored markdown is at
    /v1/agent/brief.md; this is the same text rendered."""
    c = get_context()
    async with session() as db:
        p, csrf = await principal(db, request)
    text = build_agent_brief(c.config, site_url(c, site_for(request)), c.node.network_id)
    return render(request, "agent.html", {"p": p, "csrf": csrf, "brief": text})


@router.get("/fix", response_class=HTMLResponse)
async def fix_page(request: Request):
    """How a report becomes a fix, as a page. The markdown is at /v1/agent/fix.md; same text."""
    async with session() as db:
        p, csrf = await principal(db, request)
    return render(request, "fix.html", {"p": p, "csrf": csrf, "brief": fix_brief()})


@router.get("/scope", response_class=HTMLResponse)
async def scope(request: Request):
    if r := other_site(request, "bounty", "/scope"):
        return r
    c = get_context()
    async with session() as db:
        p, csrf = await principal(db, request)
    return render(
        request,
        "scope.html",
        {"p": p, "csrf": csrf, "prog": c.config.copy_programme, "programme": c.config.programme},
    )


@router.get("/leaderboard", response_class=HTMLResponse)
async def leaderboard(request: Request):
    if r := other_site(request, "bounty", "/leaderboard"):
        return r
    async with session() as db:
        p, csrf = await principal(db, request)
        rows = await tsvc.leaderboard(db)
    return render(request, "leaderboard.html", {"p": p, "csrf": csrf, "rows": rows})


@router.get("/log", response_class=HTMLResponse)
async def log_page(request: Request, offset: int = 0, kind: str | None = None, ref: str | None = None):
    async with session() as db:
        p, csrf = await principal(db, request)
        rows = await EventLog.page(
            db, offset, 100, kind=kind, ref=ref, public_only=not can(p, "read:private")
        )
        head = await EventLog.head(db)
    # the page shows the same view of each payload as the API does: the team's layer held for others
    events = [event_to_dict(e, full=p.is_team) for e in rows]
    return render(
        request,
        "log.html",
        {"p": p, "csrf": csrf, "events": events, "offset": offset, "head": head, "kind": kind, "ref": ref},
    )


@router.get("/log/{index}", response_class=HTMLResponse)
async def log_entry(request: Request, index: int):
    async with session() as db:
        p, csrf = await principal(db, request)
        ev = await EventLog.get(db, index)
        hidden = not ev.public or is_admin_kind(ev.kind) if ev else True
        if ev is None or (hidden and not can(p, "read:private")):
            raise HTTPException(404, "no such entry")
    return render(
        request, "log_entry.html", {"p": p, "csrf": csrf, "ev": ev, "d": event_to_dict(ev, full=p.is_team)}
    )


@router.get("/live", response_class=HTMLResponse)
async def live(request: Request):
    async with session() as db:
        p, csrf = await principal(db, request)
        head = await EventLog.head(db)
    return render(request, "live.html", {"p": p, "csrf": csrf, "head": head})


# ---- reporter pages ---------------------------------------------------------------------------------


@router.get("/signin", response_class=HTMLResponse)
async def signin(request: Request, next: str | None = None):
    nxt = safe_next(get_context().settings, next, "/my")
    async with session() as db:
        p, csrf = await principal(db, request)
    if getattr(request.state, "reporter", None) is not None:
        return RedirectResponse(nxt, status_code=302)
    return render(request, "reporter/signin.html", {"p": p, "csrf": csrf, "next": nxt})


@router.get("/report", response_class=HTMLResponse)
@router.get("/ask", response_class=HTMLResponse)
async def report_form(request: Request):
    """The filing form. /report on the bounty door files a bounty report; /ask on the support door files a
    question. Each door only shows its own; the other redirects."""
    c = get_context()
    want = "support" if request.url.path == "/ask" else "bounty"
    if r := other_site(request, want, request.url.path):
        return r
    async with session() as db:
        p, csrf = await principal(db, request)
    me = getattr(request.state, "reporter", None)
    if me is None:
        return RedirectResponse(f"/signin?next={request.url.path}", status_code=302)
    return render(
        request,
        "reporter/report.html",
        {
            "p": p,
            "csrf": csrf,
            "kind": want,
            "prog": c.config.copy_programme,
            "vault_ok": c.vault.available,
            "max_mb": c.settings.max_attachment_mb,
            "max_files": c.settings.max_attachments,
        },
    )


@router.get("/my", response_class=HTMLResponse)
async def my_reports(request: Request):
    c = get_context()
    async with session() as db:
        p, csrf = await principal(db, request)
        me = getattr(request.state, "reporter", None)
        if me is None:
            return RedirectResponse("/signin?next=/my", status_code=302)
        mine = await rsvc.my_tickets(db, me)
        site = site_for(request)
        split = c.settings.hosts["bounty"] != c.settings.hosts["support"]
        rows = [t for t in mine if t.kind == site] if split else mine
        other = len(mine) - len(rows)
    return render(request, "reporter/my.html", {"p": p, "csrf": csrf, "tickets": rows, "other": other})


@router.get("/account", response_class=HTMLResponse)
async def reporter_account(request: Request):
    async with session() as db:
        p, csrf = await principal(db, request)
        me = getattr(request.state, "reporter", None)
        if me is None:
            return RedirectResponse("/signin?next=/account", status_code=302)
        n_tickets = len(await rsvc.my_tickets(db, me))
    return render(request, "reporter/account.html", {"p": p, "csrf": csrf, "n_tickets": n_tickets})


# ---- team pages -------------------------------------------------------------------------------------


@router.get("/team", response_class=HTMLResponse)
async def team_home(request: Request):
    return RedirectResponse("/?status=open&pending=true", status_code=302)


@router.get("/team/login", response_class=HTMLResponse)
async def login(request: Request, next: str = "/"):
    nxt = safe_next(get_context().settings, next, "/")
    async with session() as db:
        p, csrf = await principal(db, request)
    if p.is_team:
        return RedirectResponse(nxt, status_code=302)
    return render(request, "team/login.html", {"p": p, "csrf": csrf, "next": nxt})


@router.get("/team/invite/{token}", response_class=HTMLResponse)
async def invite(request: Request, token: str):
    async with session() as db:
        p, csrf = await principal(db, request)
    return render(request, "team/invite.html", {"p": p, "csrf": csrf, "token": token})


@router.get("/team/account", response_class=HTMLResponse)
async def account(request: Request):
    async with session() as db:
        p, csrf = await principal(db, request)
        if not p.is_team:
            return RedirectResponse("/team/login?next=/team/account", status_code=302)
        keys = await users.passkeys_for(db, p.user)
    return render(
        request, "team/account.html", {"p": p, "csrf": csrf, "keys": keys, "totp": bool(p.user.totp_secret)}
    )


@router.get("/team/tokens", response_class=HTMLResponse)
async def tokens(request: Request):
    async with session() as db:
        p, csrf = await principal(db, request)
        if not p.is_team:
            return RedirectResponse("/team/login?next=/team/tokens", status_code=302)
        rows = await users.tokens_for(db, None if can(p, "admin") else p.user)
        owners = {u.id: u for u in await users.list_users(db)}
    return render(request, "team/tokens.html", {"p": p, "csrf": csrf, "tokens": rows, "owners": owners})


@router.get("/team/users", response_class=HTMLResponse)
async def team_users(request: Request):
    async with session() as db:
        p, csrf = await principal(db, request)
        if not p.is_team:
            return RedirectResponse("/team/login?next=/team/users", status_code=302)
        rows = await users.list_users(db)
    return render(request, "team/users.html", {"p": p, "csrf": csrf, "users": rows})


@router.get("/team/release", response_class=HTMLResponse)
async def release(request: Request):
    c = get_context()
    async with session() as db:
        p, csrf = await principal(db, request)
        if not p.is_team:
            return RedirectResponse("/team/login?next=/team/release", status_code=302)
        groups = await tsvc.release_view(db, c.config, p)
        ids = [t.id for ts in groups.values() for t in ts]
        prs = await tsvc.patch_counts(db, ids)
    hours = {}
    for area, ts in groups.items():
        eng = sum(
            c.config.effort_hours(t.effort_eng)[0]
            for t in ts
            if t.status not in ("patched", "disclosed", "awarded", "paid", "closed")
        )
        agent = sum(
            c.config.effort_hours(t.effort_eng)[1]
            for t in ts
            if t.status not in ("patched", "disclosed", "awarded", "paid", "closed")
        )
        hours[area] = (eng, agent)
    return render(
        request,
        "team/release.html",
        {
            "p": p,
            "csrf": csrf,
            "groups": groups,
            "prs": prs,
            "hours": hours,
            "total": (sum(h[0] for h in hours.values()), sum(h[1] for h in hours.values())),
        },
    )


@router.get("/team/awards", response_class=HTMLResponse)
async def awards(request: Request):
    """Every valid bounty ticket that still needs an amount, or has one awaiting approval, with the
    pending award proposals beside it. Adopting sets the amount; approving is the second, separate click."""
    c = get_context()
    async with session() as db:
        p, csrf = await principal(db, request)
        if not p.is_team:
            return RedirectResponse("/team/login?next=/team/awards", status_code=302)
        rows = await tsvc.awards_due(db, c.config, p)
        approved = await tsvc.awards_approved_unawarded(db, c.config, p)
        pending = await psvc.pending_field_for(db, [t.id for t in rows], "award_xe")
        owners = await users.token_owners(db) if pending else {}
        rids = [t.reporter_id for t in rows + approved if t.reporter_id]
        reporters = {
            r.id: r
            for r in (await db.execute(select(Reporter).where(Reporter.id.in_(rids)))).scalars().all()
        } if rids else {}
    total_proposed = sum(int(prs[0].value.get("value") or 0) for prs in pending.values())
    total_set = sum((t.award_xe or 0) for t in rows) // 1_000_000
    return render(
        request,
        "team/awards.html",
        {
            "p": p,
            "csrf": csrf,
            "tickets": rows,
            "pending": pending,
            "owners": owners,
            "reporters": reporters,
            "can_award": can(p, "award"),
            "total_proposed": total_proposed,
            "total_set": total_set,
            "unset": sum(1 for t in rows if t.award_xe is None),
            "unapproved": sum(1 for t in rows if t.award_xe is not None and not t.award_approved_at),
            "approved": [(t, *tsvc.award_next_step(t)) for t in approved],
            "can_status": can(p, "status"),
        },
    )


@router.get("/team/triage", response_class=HTMLResponse)
async def triage(request: Request):
    """Everything an agent has proposed and nobody has ruled on, one row per ticket, in the views a
    reviewer works through: duplicates, closures, assessments, awards, replies. Adopting from here goes
    through the same per-proposal path as the ticket page; replies adopted here wait as drafts."""
    c = get_context()
    qp = request.query_params
    view = qp.get("view") or "all"
    if view not in psvc.TRIAGE_VIEWS:
        view = "all"
    area = qp.get("area") or None
    tier = qp.get("tier") or None
    try:
        reporter = int(qp["reporter"]) if qp.get("reporter") else None
    except ValueError:
        reporter = None
    kind = site_for(request)
    async with session() as db:
        p, csrf = await principal(db, request)
        if not p.is_team:
            return RedirectResponse("/team/login?next=/team/triage", status_code=302)
        rows = await psvc.triage_rows(
            db, c.config, p, kind=kind, view=view, area=area, tier=tier, reporter=reporter
        )
        counts = await psvc.triage_counts(db, p, kind=kind)
        owners = await users.token_owners(db) if rows else {}
        rids = {r.ticket.reporter_id for r in rows if r.ticket.reporter_id}
        reporters = {
            r.id: r
            for r in (await db.execute(select(Reporter).where(Reporter.id.in_(rids)))).scalars().all()
        } if rids else {}
    families: dict[str, list] = {}
    if view == "duplicates":
        for r in rows:
            families.setdefault(r.duplicate_of or "?", []).append(r)
    can_tier, can_award = can(p, "tier"), can(p, "award")

    def adoptable(pr) -> bool:
        if pr.field == "assessed_tier":
            return can_tier
        if pr.field == "award_xe":
            return can_award
        return True

    for r in rows:
        r.mine = [pr.id for pr in r.proposals if adoptable(pr)]
    total_xe = sum(
        int(pr.value.get("value") or 0) for r in rows for pr in r.proposals if pr.field == "award_xe"
    )

    def flt(key: str, value: str | None) -> str:
        params = {"view": view, "area": area, "tier": tier, "reporter": reporter}
        params[key] = None if str(params.get(key)) == str(value) else value  # a second click clears it
        return "/team/triage?" + "&".join(f"{k}={v}" for k, v in params.items() if v not in (None, "", "all"))

    return render(
        request,
        "team/triage.html",
        {
            "p": p,
            "csrf": csrf,
            "rows": rows,
            "families": families,
            "counts": counts,
            "view": view,
            "area": area,
            "tier": tier,
            "reporter": reporter,
            "owners": owners,
            "reporters": reporters,
            "can_tier": can_tier,
            "can_award": can_award,
            "adoptable": adoptable,
            "excerpt": psvc.note_excerpt,
            "total_xe": total_xe,
            "flt": flt,
            "views": psvc.TRIAGE_VIEWS,
        },
    )


@router.get("/team/outbox", response_class=HTMLResponse)
async def outbox(request: Request):
    c = get_context()
    async with session() as db:
        p, csrf = await principal(db, request)
        if not p.is_team:
            return RedirectResponse("/team/login?next=/team/outbox", status_code=302)
        rows = await tsvc.outbox(db, c.config, p, kind=site_for(request))
    return render(request, "team/outbox.html", {"p": p, "csrf": csrf, "tickets": rows})


# ---- a ticket, last: /{id} is the only single-segment catch-all and must not shadow the pages above ----


@router.get("/{tid}", response_class=HTMLResponse)
async def ticket_page(request: Request, tid: str):
    """A ticket lives at the bare id on its front door: /XE-0032, /XS-0001. The id already says which kind."""
    if not TICKET_ID.fullmatch(tid):
        raise HTTPException(404, "not found")
    c = get_context()
    async with session() as db:
        p, csrf = await principal(db, request)
        t = await tsvc.get_for(db, p, tid.upper())
        if tsvc.ticket_url(c, t) != f"{site_url(c, site_for(request))}{request.url.path}":
            # the other front door, lower-case, or the kind changed since the link was made: one canonical URL per ticket
            return RedirectResponse(tsvc.ticket_url(c, t), status_code=302)
        body = tsvc.body_for(c, t) if t.visibility == "public" or can(p, "read:private", t) else None
        if t.visibility == "private" and body is not None:
            await c.events.append(db, "ticket.read", p.actor, {"ticket": t.id}, ref=t.id, public=False)
            await db.commit()
        messages = [(m, thread.message_body(c, t, m)) for m in await thread.messages_for(db, t)]
        patches = await thread.patches_for(db, t)
        notes = await thread.notes_for(db, t) if can(p, "read:notes", t) else []
        proposals = await psvc.pending_for(db, t) if can(p, "read:notes", t) else []
        # the family: tickets an agent has read as re-filings of this one, waiting for one ruling
        family = await psvc.pending_duplicates_of(db, t.id) if can(p, "read:notes", t) else []
        replies = await thread.replies_for(db, t) if p.is_team else []
        dup = await tsvc.get(db, t.duplicate_of) if t.duplicate_of else None
        events = await EventLog.page(db, 0, 50, ref=t.id, **log_scope(p, t))
        team_users = await users.list_users(db) if p.is_team else []
        owners = await users.token_owners(db) if (notes or proposals or family) else {}
        reporters = await rsvc.list_for_picker(db) if p.is_team else []
        reporter = (
            (await db.execute(select(Reporter).where(Reporter.id == t.reporter_id))).scalar_one_or_none()
            if t.reporter_id
            else None
        )
        me = getattr(request.state, "reporter", None)
        mine = rsvc.owns(me, t)
        attachments = await rsvc.attachments_for(db, t) if (p.is_team or mine) else []
        # read across before ruling: what else on the desk looks like this one
        similar = await tsvc.similar(db, c.config, p, t, body=body or "") if can(p, "read:notes", t) else []
        # the other reports on the same engineering ticket: the class the fix has to close
        klass = []
        if t.internal_ref and can(p, "read:notes", t):
            siblings = (await tsvc.same_class(db, p, {t.internal_ref})).get(t.internal_ref, [])
            klass = [o for o in siblings if o.id != t.id]
    og = {}
    if t.visibility == "public":
        labels = c.config.copy_public.get("labels") or {}
        bits = [labels.get(t.status, t.status)]
        if t.kind == "bounty" and t.assessed_tier:
            bits.insert(0, c.config.tier_label(t.assessed_tier))
        og = {
            "title": f"{t.id} · {t.title}",
            "description": " · ".join(bits),
            "image": f"{site_url(c, t.kind)}/og/{t.id}.png?v={int(t.updated_at.timestamp())}",
        }
    return render(
        request,
        "ticket.html",
        {
            "p": p,
            "csrf": csrf,
            "t": t,
            "og": og,
            "body": body,
            "messages": messages,
            "patches": patches,
            "notes": notes,
            "similar": similar,
            "klass": klass,
            "proposals": proposals,
            "family": family,
            "replies": replies,
            "dup": dup,
            "events": events,
            "team_users": team_users,
            "owners": owners,
            "reporter": reporter,
            "reporters": reporters,
            "mine": mine,
            "attachments": attachments,
            "can_withdraw": mine and t.status in rsvc.OPEN_FOR_REPORTER,
            "url": tsvc.ticket_url(c, t),
            "internal_url": c.settings.internal_url(t.internal_ref),
            "tier_fields": ("assessed_tier",),
            "award_block": tsvc.award_approvable(t) if t.kind == "bounty" else None,
            "award_step": tsvc.award_next_step(t)[0] if t.kind == "bounty" else "",
        },
    )

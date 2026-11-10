"""`desk` command line: keys, users and invites, tokens, GitHub and triage import, export, log
verification, copy lint, health. Runs inside the app container against the same database."""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import sys
from dataclasses import replace
from pathlib import Path

import typer

app = typer.Typer(help="XE desk tools", no_args_is_help=True)
keys_app = typer.Typer(
    help="Keyfile: log (signs the chain) and vault (seals private bodies)", no_args_is_help=True
)
users_app = typer.Typer(help="Team accounts", no_args_is_help=True)
tokens_app = typer.Typer(help="Agent tokens", no_args_is_help=True)
app.add_typer(keys_app, name="keys")
app.add_typer(users_app, name="users")
app.add_typer(tokens_app, name="tokens")


def _settings():
    from .settings import get_settings

    return get_settings()


def _passphrase(explicit: str | None) -> str:
    return explicit or os.environ.get("DESK_SIGNER_PASSPHRASE") or getpass.getpass("signer passphrase: ")


def _ctx():
    from .context import build_context, set_context

    ctx = build_context()
    set_context(ctx)
    return ctx


def _run(coro):
    return asyncio.run(coro)


# ---- keys -------------------------------------------------------------------------------------


@keys_app.command("init")
def keys_init(
    path: Path = typer.Option(None, help="defaults to DESK_SIGNER_KEYFILE"),
    passphrase: str = typer.Option(None),
):
    """Create the encrypted keyfile with the log and vault keys. Prints the log public key to publish."""
    from .signer import Signer

    p = path or _settings().signer_keyfile
    p.parent.mkdir(parents=True, exist_ok=True)
    infos = Signer.init_keyfile(p, _passphrase(passphrase))
    typer.echo(f"wrote {p}")
    for i in infos.values():
        typer.echo(f"  {i.name:8} pub {i.public_key}  scopes {','.join(i.scopes)}")
    typer.echo(
        "\nBack the file and the passphrase up separately. Losing the vault key loses every private report."
    )


@keys_app.command("show")
def keys_show(path: Path = typer.Option(None), passphrase: str = typer.Option(None)):
    from .signer import Signer

    s = Signer.load(path or _settings().signer_keyfile, _passphrase(passphrase))
    for i in s.infos():
        typer.echo(f"{i.name:8} pub {i.public_key}  scopes {','.join(i.scopes)}")


# ---- users ------------------------------------------------------------------------------------


@users_app.command("add")
def users_add(
    email: str,
    name: str = typer.Option("", "--name"),
    roles: str = typer.Option("reviewer", help="comma-separated"),
):
    """Add a team member and print a one-time invite link."""

    async def go():
        from . import auth
        from .db import session
        from .services import users

        ctx = _ctx()
        async with session() as db:
            u = await users.create_user(
                ctx, db, "cli", email, name, [r.strip() for r in roles.split(",") if r.strip()]
            )
            raw = await auth.create_invite(db, u, "invite")
            await ctx.events.append(db, "team.invited", "cli", {"user": u.id}, public=False)
            await db.commit()
            typer.echo(f"user {u.id} {u.email} roles {u.roles}")
            typer.echo(f"invite: {ctx.settings.scheme}://{ctx.settings.hosts['bounty']}/team/invite/{raw}")
        await ctx.aclose()

    _run(go())


@users_app.command("invite")
def users_invite(email: str):
    """A fresh invite link for an existing member (lost passkey, new device)."""

    async def go():
        from . import auth
        from .db import session
        from .services import users

        ctx = _ctx()
        async with session() as db:
            u = await users.by_email(db, email)
            if u is None:
                typer.echo("no such user", err=True)
                raise typer.Exit(1)
            raw = await auth.create_invite(db, u, "invite")
            await ctx.events.append(db, "team.invited", "cli", {"user": u.id}, public=False)
            await db.commit()
            typer.echo(f"invite: {ctx.settings.scheme}://{ctx.settings.hosts['bounty']}/team/invite/{raw}")
        await ctx.aclose()

    _run(go())


@users_app.command("roles")
def users_roles(email: str, roles: str):
    async def go():
        from .db import session
        from .services import users

        ctx = _ctx()
        async with session() as db:
            u = await users.by_email(db, email)
            if u is None:
                typer.echo("no such user", err=True)
                raise typer.Exit(1)
            await users.set_roles(ctx, db, "cli", u, [r.strip() for r in roles.split(",") if r.strip()])
            await db.commit()
            typer.echo(f"{u.email} roles {u.roles}")
        await ctx.aclose()

    _run(go())


@users_app.command("rename")
def users_rename(email: str, name: str):
    """Change the name a member's replies are sent under."""

    async def go():
        from .db import session
        from .services import users

        ctx = _ctx()
        async with session() as db:
            u = await users.by_email(db, email)
            if u is None:
                typer.echo("no such user", err=True)
                raise typer.Exit(1)
            await users.set_name(ctx, db, "cli", u, name)
            await db.commit()
            typer.echo(f"{u.email} is now {u.name!r}")
        await ctx.aclose()

    _run(go())


@users_app.command("list")
def users_list():
    async def go():
        from .db import session
        from .services import users

        ctx = _ctx()
        async with session() as db:
            for u in await users.list_users(db):
                typer.echo(
                    f"{u.id:4} {u.email:40} {u.name:24} {','.join(u.roles):30} {'active' if u.active else 'inactive'}"
                )
        await ctx.aclose()

    _run(go())


# ---- tokens -----------------------------------------------------------------------------------


@tokens_app.command("issue")
def tokens_issue(
    owner_email: str,
    model_id: str,
    label: str = typer.Option("", "--label"),
    scopes: str = typer.Option("read:public,write:notes,write:proposals"),
    days: int = typer.Option(90),
):
    """Issue an agent token bound to a team member. Printed once."""

    async def go():
        from .authz import SYSTEM
        from .db import session
        from .services import users

        ctx = _ctx()
        async with session() as db:
            owner = await users.by_email(db, owner_email)
            if owner is None:
                typer.echo("no such user", err=True)
                raise typer.Exit(1)
            p = replace(SYSTEM, user=owner)
            t, raw = await users.issue(
                ctx, db, p, owner, model_id, label, [s.strip() for s in scopes.split(",") if s.strip()], days
            )
            await db.commit()
            typer.echo(
                f"token {t.id} for {owner.email} model {t.model_id} scopes {t.scopes} expires {t.expires_at.date()}"
            )
            typer.echo(raw)
        await ctx.aclose()

    _run(go())


@tokens_app.command("revoke")
def tokens_revoke(token_id: int):
    async def go():
        from .authz import SYSTEM
        from .db import session
        from .services import users

        ctx = _ctx()
        async with session() as db:
            t = await users.token_by_id(db, token_id)
            if t is None:
                typer.echo("no such token", err=True)
                raise typer.Exit(1)
            p = replace(SYSTEM, user=await users.by_id(db, t.owner_id))
            await users.revoke(ctx, db, p, t)
            await db.commit()
            typer.echo(f"revoked {t.id}")
        await ctx.aclose()

    _run(go())


@tokens_app.command("list")
def tokens_list():
    async def go():
        from .db import session
        from .services import users

        ctx = _ctx()
        async with session() as db:
            for t in await users.tokens_for(db):
                state = "revoked" if t.revoked_at else "active"
                typer.echo(
                    f"{t.id:4} {t.prefix:14} {t.model_id:24} {t.label:20} {','.join(t.scopes):60} {t.expires_at.date()} {state}"
                )
        await ctx.aclose()

    _run(go())


# ---- imports ----------------------------------------------------------------------------------


@app.command("import-github")
def import_github(
    repo: str = typer.Option(None, help="owner/repo; defaults to every repo in desk.yaml"),
    full: bool = typer.Option(False, help="ignore the saved cursor and re-read everything"),
):
    """Pull issues, comments and PR links from GitHub into tickets. Idempotent."""

    async def go():
        from .db import session
        from .services import github as gh
        from .services import sync

        ctx = _ctx()
        if not ctx.settings.github_token:
            typer.echo("GITHUB_TOKEN is not set", err=True)
            raise typer.Exit(1)
        client = gh.GitHub(ctx.settings.github_token)
        repos = [repo] if repo else ctx.config.repos
        async with session() as db:
            for r in repos:
                since = None if full else (await sync.get_cursor(db, f"github:{r}:issues") or None)
                stats = await sync.import_repo(ctx, db, client, r, since=since)
                typer.echo(json.dumps(stats))
        await client.aclose()
        await ctx.aclose()

    _run(go())


@app.command("import-internal")
def import_internal(
    full: bool = typer.Option(False, help="ignore the saved cursor and re-read every internal ticket"),
):
    """Read the engineering tracker (config: internal.repo). An internal ticket that names a public
    report ("xe#8") fills that ticket's internal_ref; its open/closed state moves the ticket's status.
    Read-only towards the tracker. Idempotent."""

    async def go():
        from .db import session
        from .services import github as gh
        from .services import sync

        ctx = _ctx()
        if not ctx.settings.github_token:
            typer.echo("GITHUB_TOKEN is not set", err=True)
            raise typer.Exit(1)
        if not ctx.config.internal_repo:
            typer.echo("internal.repo is not set in config/desk.yaml", err=True)
            raise typer.Exit(1)
        client = gh.GitHub(ctx.settings.github_token)
        async with session() as db:
            key = f"github:{ctx.config.internal_repo}:issues"
            since = None if full else (await sync.get_cursor(db, key) or None)
            typer.echo(json.dumps(await sync.import_internal(ctx, db, client, since=since)))
        await client.aclose()
        await ctx.aclose()

    _run(go())


@app.command("import-triage")
def import_triage(
    path: Path = typer.Argument(Path("/app/secrets/BOUNTY_TRIAGE.md")),
    emails: Path = typer.Option(None, help="JSON {E1: body, E2: body, E3: body} for the private tickets"),
    dry_run: bool = typer.Option(False, help="parse and print the rows; write nothing"),
):
    """Apply the triage doc: facts, status, notes, patch links. Run after import-github. Re-runnable."""
    from .services import triage

    rows = triage.parse_triage(path.read_text(encoding="utf-8"))
    if dry_run:
        for r in rows:
            st, reason = r.status()
            typer.echo(
                f"{r.key:>4} {r.kind:7} {st:9} {reason or '':9} {r.verdict or '-':12} {r.gate or '-':6} "
                f"{r.claimed_tier or '-':8}->{r.assessed_tier or '-':8} {r.effort or '-':7} int={r.internal_ref or '-':11} "
                f"{r.internal_state or '-':7} prs={[p.repo.split('/')[-1] + '#' + p.ref for p in r.patches]} "
                f"fix={r.internal_fix_prs} dup={r.duplicate_of_key or '-'} area={r.area}"
            )
        typer.echo(f"{len(rows)} rows")
        return

    async def go():
        from .db import session

        ctx = _ctx()
        bodies = json.loads(emails.read_text(encoding="utf-8")) if emails else {}
        async with session() as db:
            stats = await triage.import_rows(ctx, db, rows, email_bodies=bodies)
            await db.commit()
        typer.echo(json.dumps(stats))
        await ctx.aclose()

    _run(go())


@app.command("export-triage")
def export_triage(out: Path = typer.Option(None, help="write here instead of stdout")):
    async def go():
        from .authz import SYSTEM
        from .db import session
        from .services import triage

        ctx = _ctx()
        async with session() as db:
            text = await triage.export_markdown(ctx, db, SYSTEM)
        if out:
            out.write_text(text, encoding="utf-8")
            typer.echo(f"wrote {out}")
        else:
            sys.stdout.write(text)
        await ctx.aclose()

    _run(go())


@app.command("tell-backlog")
def tell_backlog(
    dry_run: bool = typer.Option(False, help="list what would be sent, what is left and why; send nothing"),
):
    """Send the stock accepted or patched reply on every ticket that was already resting untold when
    the desk began telling on its own (the worker only tells moves made since). The rule is the
    worker's (services/tell.py): what a person has in hand, or the desk cannot say, is left, and the
    dry run says why. Replies go out as any reply does: a GitHub comment by the worker, a mail from
    here. Re-runnable; a ticket that has been told is not told twice."""

    async def go():
        from .db import session
        from .services import notify, tell
        from .services import tickets as tsvc

        ctx = _ctx()
        async with session() as db:
            if dry_run:
                rows = await tell.resting(ctx, db, now=tsvc.utcnow())
                for r in rows:
                    t = r.ticket
                    what = "tell" if r.text else f"left: {r.why}"
                    typer.echo(f"{r.id}  {r.status:8}  {t.source:8}  {t.visibility:7}  {what}")
                n = sum(1 for r in rows if r.text)
                typer.echo(f"{n} would be told, {len(rows) - n} left for a person")
            else:
                total = mailed = 0
                while True:
                    told = await tell.tell_resting(ctx, db, backlog=True)
                    owed = notify.take_owed(db)
                    await db.commit()  # a batch at a time: what is mailed below is what was committed
                    for x in told:
                        typer.echo(f"{x['ticket']}  {x['status']:8}  told (reply {x['reply']})")
                    mailed += await notify.mail_owed(ctx, owed)
                    total += len(told)
                    if len(told) < tell.BATCH:
                        break
                typer.echo(f"{total} told, {mailed} mailed")
        await ctx.aclose()

    _run(go())


@app.command("github-labels")
def github_labels():
    """Create or update the desk's status labels on every configured repo."""

    async def go():
        from .services import github as gh

        ctx = _ctx()
        client = gh.GitHub(ctx.settings.github_token)
        for repo in ctx.config.repos:
            await client.ensure_labels(repo, ctx.config.all_labels())
            typer.echo(f"{repo}: {len(ctx.config.all_labels())} labels ensured")
        await client.aclose()
        await ctx.aclose()

    _run(go())


# ---- checks -----------------------------------------------------------------------------------


@app.command("verify-log")
def verify_log():
    async def go():
        from .db import session
        from .log import EventLog

        ctx = _ctx()
        async with session() as db:
            r = await EventLog.verify(db, ctx.signer.public_key("log") if ctx.signer.has("log") else "")
        typer.echo(json.dumps(r))
        await ctx.aclose()
        if not r["ok"]:
            raise typer.Exit(1)

    _run(go())


@app.command("copy-lint")
def copy_lint():
    """Fail if the public register or any template contains a kill-list phrase."""
    from .config import load_config, strip_template
    from .main import HERE

    cfg = load_config(_settings().config_dir)
    texts = [strip_template(p.read_text(encoding="utf-8")) for p in (HERE / "templates").rglob("*.html")]
    from .config import lint_public_copy

    v = lint_public_copy(cfg, texts)
    for line in v:
        typer.echo(line)
    typer.echo(f"{len(v)} violation(s)")
    if v:
        raise typer.Exit(1)


@app.command("bot-discord")
def bot_discord():
    """Run the Discord support bot (the `bot` compose service does this)."""
    from .bots.discord_bot import main

    _run(main())


@app.command("health")
def health():
    async def go():
        from .db import session
        from .log import EventLog

        ctx = _ctx()
        node = await ctx.refresh_node()
        async with session() as db:
            head = await EventLog.head(db)
        typer.echo(
            json.dumps(
                {
                    "network_id": node.network_id,
                    "node": ctx.settings.xe_node_url,
                    "log_head": head.index,
                    "signer": ctx.signer.has("log"),
                    "vault": ctx.vault.available,
                    "hosts": ctx.settings.hosts,
                    "config_hashes": ctx.config.hashes,
                },
                indent=2,
            )
        )
        await ctx.aclose()

    _run(go())


if __name__ == "__main__":
    app()

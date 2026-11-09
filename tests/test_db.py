"""Against a real Postgres: the log chain, the ticket flow, proposals, the outbox, and the triage import
of the actual doc. Skipped unless DESK_TEST_DATABASE_URL is set, e.g.
DESK_TEST_DATABASE_URL=postgresql+asyncpg://desk:pw@db:5432/desk_test (a scratch database; it is wiped).

The image carries neither pytest nor this directory; mount the tests and install pytest for the run.
Build first, or the tests run against whatever code the image was last built from. On the VPS (see
docs/DEPLOY.md):

  docker compose build app
  docker compose exec db psql -U desk -d desk -c "CREATE DATABASE desk_test"   # "already exists" is fine
  docker compose run --rm --no-deps -v $PWD/tests:/app/tests \
    -e DESK_TEST_DATABASE_URL=postgresql+asyncpg://desk:$(grep ^POSTGRES_PASSWORD .env | cut -d= -f2)@db:5432/desk_test \
    app sh -c "pip install -q pytest pytest-asyncio && pytest -q tests/test_db.py"
"""

import asyncio
import hashlib
import json
import os
import time
from collections import Counter
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from desk import auth, authz
from desk.auth import SignedRequest, signing_target, verify_signed
from desk.canonical import DOMAIN_LOGIN, DOMAIN_PAYOUT
from desk.config import load_config
from desk.context import Context, NodeIdentity
from desk.db import Base
from desk.log import EventLog
from desk.models import AgentToken, Event, Note, Proposal, Reply, Ticket, User
from desk.services import proposals as psvc
from desk.services import channels
from desk.services import reporters as rsvc
from desk.services import notify, sync, thread, triage, users
from desk.services import tickets as tsvc
from desk.services.tickets import utcnow
from desk.settings import Settings
from desk.signer import Signer
from desk.vault import Vault
from xe.keys import KeyPair

URL = os.environ.get("DESK_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="DESK_TEST_DATABASE_URL not set")
ROOT = Path(__file__).resolve().parents[1]


class _NoChain:
    async def node(self):
        return {"network_id": "testnet-0005", "id": "x", "version": "t"}

    async def aclose(self):
        pass


@pytest.fixture
async def db():
    eng = create_async_engine(URL)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("INSERT INTO log_head (id, index, hash) VALUES (1, -1, repeat('0', 64))"))
        await conn.execute(text("INSERT INTO id_counters (kind, next) VALUES ('bounty', 1), ('support', 1)"))
    sm = async_sessionmaker(eng, expire_on_commit=False)
    async with sm() as s:
        yield s
    await eng.dispose()


@pytest.fixture
def ctx():
    signer = Signer(
        {"log": KeyPair.generate(), "vault": KeyPair.generate()},
        {"log": {"event.sign"}, "vault": {"vault.seal", "vault.open"}},
    )
    settings = Settings(
        DESK_BOUNTY_HOST="bounty.test",
        DESK_SUPPORT_HOST="support.test",
        PUBLIC_BASE_URL="https://bounty.test",
    )
    c = Context(
        settings=settings,
        config=load_config(ROOT / "config"),
        signer=signer,
        vault=Vault(signer),
        chain=_NoChain(),
        events=EventLog(signer),
        node=NodeIdentity(network_id="testnet-0005"),
    )
    return c


async def _team(ctx, db, roles=("reviewer", "tier", "treasurer", "admin"), email="lead@xe.network"):
    """A team member. A second call in the same test needs its own email; one is derived from the roles."""
    if await users.by_email(db, email):
        email = "-".join(sorted(roles)) + "@xe.network"
    u = await users.create_user(ctx, db, "test", email, "Lead", list(roles))
    return authz.Principal(kind="user", user=u, roles=set(roles))


async def _agent(ctx, db, owner: User, scopes=("read:public", "write:notes", "write:proposals")):
    tok, _raw = await users.issue(
        ctx, db, authz.Principal(kind="user", user=owner, roles={"admin"}), owner, "m", "t", list(scopes), 30
    )
    return authz.Principal(kind="token", token=tok, scopes=set(scopes))


# ---- log --------------------------------------------------------------------------------------------


async def test_log_chain_verifies_and_detects_tamper(ctx, db):
    for i in range(4):
        await ctx.events.append(db, "test", "desk", {"i": i}, public=(i % 2 == 0))
    await db.commit()
    res = await EventLog.verify(db)
    assert res["ok"] and res["count"] == 4
    assert len(await EventLog.since(db, -1, public_only=True)) == 2
    key = ctx.signer.public_key("log")
    assert (await EventLog.verify(db, key))["ok"]
    # the envelope covers the private flag and the ref: declassifying a row is a hash mismatch
    await db.execute(text("UPDATE events SET public = true WHERE index = 1"))
    await db.commit()
    assert "hash mismatch at 1" in (await EventLog.verify(db, key))["first_error"]
    await db.execute(text("UPDATE events SET public = false WHERE index = 1"))
    await db.execute(text("UPDATE events SET payload = '{\"i\": 9}'::jsonb WHERE index = 2"))
    await db.commit()
    assert "hash mismatch at 2" in (await EventLog.verify(db))["first_error"]
    # a stripped signature, or one by another key, fails against the published key
    await db.execute(text("UPDATE events SET payload = '{\"i\": 2}'::jsonb WHERE index = 2"))
    await db.execute(text("UPDATE events SET signature = '' WHERE index = 2"))
    await db.commit()
    assert (await EventLog.verify(db))["ok"]  # unpinned: tolerated, as a dev desk without a key would be
    assert "not signed by the log key" in (await EventLog.verify(db, key))["first_error"]


def test_event_views_hide_operational_fields_from_non_team():
    from desk.log import event_to_dict
    from desk.models import Event

    ev = Event(
        index=1, ts=1, kind="reporter.login", actor="reporter:1", payload={"how": "email", "ip": "10.0.0.9"},
        prev_hash="0" * 64, hash="1" * 64, signer="", signature="", public=False, ref="", v=2,
    )
    assert event_to_dict(ev)["payload"]["ip"] == "10.0.0.9"
    assert "ip" not in event_to_dict(ev, full=False)["payload"]
    # a public fact change names which assessment fields moved, not what they became or why
    facts = Event(
        index=2, ts=2, kind="ticket.facts", actor="user:1", prev_hash="1" * 64, hash="2" * 64, signer="",
        signature="", public=True, ref="XE-0001", v=2,
        payload={
            "ticket": "XE-0001", "reason": "confirmed at ledger.go:2117", "via": "",
            "changes": {"assessed_tier": {"from": None, "to": "high"}, "area": {"from": None, "to": "core"}},
        },
    )
    full = event_to_dict(facts)["payload"]
    assert full["changes"]["assessed_tier"]["to"] == "high" and full["reason"]
    pub = event_to_dict(facts, full=False)["payload"]
    assert pub["changes"] == {"area": {"from": None, "to": "core"}} and pub["held"] == ["assessed_tier"]
    assert "reason" not in pub and pub["ticket"] == "XE-0001"
    prop = Event(
        index=3, ts=3, kind="proposal.created", actor="token:1", prev_hash="2" * 64, hash="3" * 64, signer="",
        signature="", public=True, ref="XE-0001", v=2,
        payload={"ticket": "XE-0001", "proposal": 1, "field": "assessed_tier", "value": "critical"},
    )
    assert "value" not in event_to_dict(prop, full=False)["payload"]
    assert event_to_dict(prop, full=False)["payload"]["field"] == "assessed_tier"
    # the team's administration shrinks to ids outside the team: no addresses, roles, labels or scopes
    admin = Event(
        index=4, ts=4, kind="token.issued", actor="user:1", prev_hash="3" * 64, hash="4" * 64, signer="",
        signature="", public=True, ref="", v=2,
        payload={"token": 4, "owner": 2, "model": "claude", "label": "daily", "scopes": ["read:private"]},
    )
    assert event_to_dict(admin, full=False)["payload"] == {"token": 4, "owner": 2}


# ---- tickets ----------------------------------------------------------------------------------------


async def test_ticket_lifecycle(ctx, db):
    p = await _team(ctx, db)
    t = await tsvc.create(
        ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="A crash", body="steps", source="web")
    )
    assert t.id == "XE-0001"
    t2 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="support", title="Faucet?", source="web"))
    assert t2.id == "XS-0001"
    await tsvc.set_facts(
        ctx,
        db,
        p,
        t,
        {"verdict": "valid", "assessed_tier": "high", "mainnet_gate": "before", "area": "node-api"},
    )
    with pytest.raises(HTTPException):
        await tsvc.set_facts(ctx, db, p, t, {"assessed_tier": "enormous"})
    with pytest.raises(HTTPException):
        await tsvc.set_status(ctx, db, p, t, "paid")
    await tsvc.set_status(ctx, db, p, t, "triaging")
    await tsvc.set_status(ctx, db, p, t, "accepted")
    await tsvc.set_facts(ctx, db, p, t, {"internal_ref": "#1068", "effort_eng": "1-4h"})
    # accepted and unfixed: the team sees the assessment, the public sees the ticket and no ranking
    mine, theirs = tsvc.to_dict(ctx, t, p), tsvc.to_dict(ctx, t, authz.ANON)
    assert mine["assessed_tier"] == "high" and mine["mainnet_gate"] == "before"
    assert mine["internal_ref"] == "#1068"
    assert theirs["assessed_tier"] is None and theirs["verdict"] is None and theirs["internal_ref"] == ""
    assert theirs["tracked"] is True and "mainnet_gate" not in theirs and "effort_eng" not in theirs
    assert "assignee_id" not in theirs
    await tsvc.set_status(ctx, db, p, t, "patched")
    assert t.status_changed_at is not None
    theirs = tsvc.to_dict(ctx, t, authz.ANON)
    assert theirs["assessed_tier"] == "high" and theirs["verdict"] == "valid"
    assert theirs["internal_ref"] == "#1068"
    assert "mainnet_gate" not in theirs  # planning data, never public
    # outbox: patched and never told
    assert [x.id for x in await tsvc.outbox(db, ctx.config, p)] == ["XE-0001"]
    r = await thread.add_reply(ctx, db, p, t, "Fixed in #27, thank you.")
    assert r.mirror == "none" and t.told_at is not None
    assert await tsvc.outbox(db, ctx.config, p) == []
    # a withdrawal is the reporter's own word: closed, never told, and still not owed a reply
    t3 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="Test", source="web"))
    await tsvc.set_status(ctx, db, p, t3, "triaging")
    await tsvc.set_status(ctx, db, p, t3, "closed", closed_reason="withdrawn")
    assert await tsvc.outbox(db, ctx.config, p) == []
    # award needs the treasurer and approval before awarded
    with pytest.raises(HTTPException):
        await tsvc.set_status(ctx, db, p, t, "awarded")
    t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
    await tsvc.set_award(ctx, db, p, t, 5_000_000_000, approve=True)
    await tsvc.set_status(ctx, db, p, t, "awarded")
    await db.commit()
    # The status/award routes return to_dict after commit. updated_at is server-set on UPDATE; without
    # eager_defaults it is expired at flush and this read would be an implicit refresh, which an async
    # session turns into MissingGreenlet: a 500 after the write landed. Must read cleanly here.
    d = tsvc.to_dict(ctx, t, p)
    assert d["status"] == "awarded" and d["award_xe"] == 5_000_000_000 and d["updated_at"]
    board = await tsvc.leaderboard(db)
    assert board == []  # no reporter attached
    kinds = Counter(e.kind for e in await EventLog.page(db, 0, 100, ref=t.id))
    assert (
        kinds["ticket.status"] == 4
        and kinds["ticket.facts"] == 2  # the first assessment, then the internal ref and effort
        and kinds["reply.sent"] == 1
        and kinds["ticket.award"] == 1
    )


async def test_counts_split_into_now_and_all_time(ctx, db):
    """Open is what is still being worked. Fixed, awarded and closed are all-time and never shrink as a
    ticket moves from the merge to the money. The list filters use the same split."""
    p = await _team(ctx, db)
    new = [tsvc.NewTicket(kind="bounty", title=n, source="web") for n in "abcd"]
    a, b, c, d = [await tsvc.create(ctx, db, p.actor, n) for n in new]
    for t, path in ((a, ["triaging", "accepted"]), (b, ["triaging", "accepted", "patched"]),
                    (c, ["triaging", "accepted", "patched", "awarded", "paid"])):
        for st in path:
            await tsvc.set_status(ctx, db, p, t, st, force=True)  # awarded/paid without the treasurer's click
    await tsvc.set_status(ctx, db, p, d, "closed", closed_reason="invalid")
    n = await tsvc.counts(db, p)
    assert (n["open"], n["fixed"], n["awarded_all"], n["closed"]) == (1, 2, 1, 1)
    assert n["open"] == n["new"] + n["triaging"] + n["needs-info"] + n["accepted"] + n["fixing"]
    async def ids(status):
        return {r.id for r in await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters(status=status))}

    assert await ids("open") == {a.id}
    assert await ids("fixed") == {b.id, c.id}
    assert await ids("closed") == {d.id}


async def test_a_report_is_read_across_the_desk(ctx, db):
    """Before a verdict the reader is shown what else looks like the report: shared words, shared paths,
    the same reporter, duplicate links; the search reaches bodies; a page says how many there are in all;
    and the export means every ticket."""
    from desk.models import Reporter

    p = await _team(ctx, db)
    r1, r2 = Reporter(github_login="ada"), Reporter(github_login="mallory")
    db.add_all([r1, r2])
    await db.flush()

    async def mk(title, body="", reporter=None, area=None, visibility="public"):
        spec = tsvc.NewTicket(
            kind="bounty", title=title, body=body, source="web", reporter_id=reporter and reporter.id,
            area=area, visibility=visibility,
        )
        return await tsvc.create(ctx, db, p.actor, spec)

    a = await mk(
        "Quorum bypass via hex vote forgery", "A forged vote in src/consensus/vote.rs:120 counts twice.",
        r1, "consensus",
    )
    b = await mk("Vote malleability lets one validator vote twice",
                 "The check in src/consensus/vote.rs accepts both encodings.", r2, "consensus")
    c = await mk("Sync stalls on a bad peer", "crates/p2p/sync.go never times out.", r1, "p2p-sync")
    d = await mk("Unrelated typo on the docs page", "The scope page says 'teh'.", None, "sdk-docs-web")
    e = await mk("Private: quorum vote forgery, again", "", r2, "consensus", visibility="private")
    await db.commit()

    rows = await tsvc.similar(db, ctx.config, p, a, body=a.body)
    by = {s.ticket.id: s for s in rows}
    assert b.id in by and "same words" in by[b.id].why and "same area" in by[b.id].why
    assert "cites src/consensus/vote.rs" in by[b.id].why
    assert c.id in by and by[c.id].why == ["same reporter"]
    assert d.id not in by
    assert rows[0].ticket.id == b.id  # the strongest match leads
    # a reader without read:private is not shown the private one; the team is, by its title alone
    assert e.id in by
    assert e.id not in {s.ticket.id for s in await tsvc.similar(db, ctx.config, authz.ANON, a, body=a.body)}
    # a duplicate link counts either way round
    await tsvc.set_facts(ctx, db, p, b, {"duplicate_of": a.id})
    again = {s.ticket.id: s for s in await tsvc.similar(db, ctx.config, p, a)}
    assert "linked as duplicate" in again[b.id].why
    row = tsvc.similar_dict(ctx, by[b.id], authz.ANON, a)
    assert row["same_reporter"] is False and "internal_ref" not in row  # held while the bug is open
    # the search reaches public bodies
    hits = {t.id for t in await tsvc.list_tickets(db, ctx.config, authz.ANON, tsvc.Filters(q="encodings"))}
    assert hits == {b.id}
    # one reporter's filings, for the team only
    hers = tsvc.Filters(status="all", reporter=r1.id)
    assert {t.id for t in await tsvc.list_tickets(db, ctx.config, p, hers)} == {a.id, c.id}
    with pytest.raises(HTTPException) as e:  # a public caller is refused the axis, not given the unfiltered set (XE-1560)
        await tsvc.list_tickets(db, ctx.config, authz.ANON, hers)
    assert e.value.status_code == 403
    # a page knows the size of the whole selection
    f = tsvc.Filters(status="all", limit=2)
    assert len(await tsvc.list_tickets(db, ctx.config, p, f)) == 2
    assert await tsvc.count_tickets(db, ctx.config, p, f) == 5
    # the export reads every page, not the first
    assert len(await triage.all_tickets(db, ctx.config, p, page=2)) == 5
    assert "5 tickets." in await triage.export_markdown(ctx, db, p)


async def test_a_note_says_what_it_checked(ctx, db):
    p = await _team(ctx, db)
    agent = await _agent(ctx, db, p.user)
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    seen = {"desk": 692, "similar": ["xe-0130", "XE-0131"], "tracker": False, "tree": "xe@abc1234"}
    n = await thread.add_note(ctx, db, agent, t, "Read.", seen)
    assert n.checked == {**seen, "similar": ["XE-0130", "XE-0131"]}
    assert (await thread.add_note(ctx, db, agent, t, "Remark.")).checked == {}
    for bad in ({"desk": "many"}, {"tracker": 1}, {"tree": 7}, {"github": True}, ["desk"]):
        with pytest.raises(HTTPException):
            await thread.add_note(ctx, db, agent, t, "x", bad)


async def test_team_administration_never_reaches_the_public_log(ctx, db):
    p = await _team(ctx, db)
    tok = await _agent(ctx, db, p.user)
    await users.set_roles(ctx, db, p.actor, p.user, [])  # no roles: the token dies with them
    mine = {e.kind for e in await EventLog.page(db, 0, 200, public_only=False)}
    assert {"user.created", "token.issued", "user.roles", "token.revoked"} <= mine
    theirs = await EventLog.page(db, 0, 200, public_only=True)
    assert not any(e.kind.startswith(("user.", "token.", "team.")) for e in theirs)
    latest = await EventLog.since(db, 0, public_only=True)
    assert not any(e.kind.startswith(("user.", "token.")) for e in latest)
    # rows written public before the rule are still held back: the rule is in the read path
    row = (await db.execute(select(Event).where(Event.kind == "user.created"))).scalars().first()
    row.public = True
    await db.flush()
    assert not any(e.kind == "user.created" for e in await EventLog.page(db, 0, 200, public_only=True))
    assert tok.token is not None


async def test_private_ticket_is_sealed_and_hidden(ctx, db):
    p = await _team(ctx, db)
    t = await tsvc.create(
        ctx,
        db,
        p.actor,
        tsvc.NewTicket(
            kind="bounty",
            title="secret",
            body="the exploit",
            visibility="private",
            source="email",
            source_ref="E9",
        ),
    )
    assert t.body == "" and t.body_sealed and tsvc.body_for(ctx, t) == "the exploit"
    row = (await db.execute(text("SELECT body, body_sealed FROM tickets WHERE id = :id"), {"id": t.id})).one()
    assert row[0] == "" and b"exploit" not in bytes(row[1])
    assert await tsvc.list_tickets(db, ctx.config, authz.ANON, tsvc.Filters(status="all")) == []
    with pytest.raises(HTTPException) as e:
        await tsvc.get_for(db, authz.ANON, t.id)
    assert e.value.status_code == 404
    evs = await EventLog.page(db, 0, 10, ref=t.id, public_only=True)
    assert evs == []


async def test_private_history_leaves_the_public_log_and_replies_seal(ctx, db):
    team = await _team(ctx, db)
    t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(79, "public first", body="b"))
    await tsvc.set_status(ctx, db, team, t, "triaging")
    r = await thread.add_reply(ctx, db, team, t, "public words")
    assert (await EventLog.page(db, 0, 50, ref=t.id)) != []
    await tsvc.set_facts(ctx, db, team, t, {"visibility": "private"})
    # the history is gone from every public read path while the ticket is private; the one row that stays
    # says why (XE-0350, XE-0410)
    pub = await EventLog.page(db, 0, 50, ref=t.id)
    assert [e.kind for e in pub] == ["ticket.sealed"]
    sealed = pub[0]
    assert await EventLog.served_public(db, sealed) is True
    every = await EventLog.page(db, 0, 50, ref=t.id, public_only=False)
    created = next(e for e in every if e.kind == "ticket.created")
    assert created.public is True and await EventLog.served_public(db, created) is False
    assert all(e.ref != t.id or e.kind == "ticket.sealed" for e in await EventLog.since(db, -1, 1000))
    # the reply row followed the body into the vault (XE-0426), and a new reply on a private ticket seals
    await db.refresh(r)
    assert r.body == "" and r.body_sealed and thread.reply_body(ctx, r) == "public words"
    r2 = await thread.add_reply(ctx, db, team, t, "private words")
    assert r2.body == "" and thread.reply_body(ctx, r2) == "private words"
    # disclosed again: the history is served again
    await thread.add_patch_ref(ctx, db, team, t, repo="xeprotocol/xe", ref="9", kind="pr")
    for st in ("accepted", "patched"):
        await tsvc.set_status(ctx, db, team, t, st)
    await tsvc.set_status(ctx, db, team, t, "disclosed")
    assert await EventLog.served_public(db, created) is True
    # the chain still verifies: nothing was rewritten
    assert (await EventLog.verify(db))["ok"]


async def test_the_live_stream_serves_only_what_the_log_read_path_serves(ctx, db, monkeypatch):
    """The rule: an event reaches a reader outside the team only through the log's one read path (stored
    flag, admin kinds, the ticket's visibility now). The SSE stream used to trust the stored flag on the
    live branch (XE-1884, XE-1641, XE-1645); now replay and live both read back through `since`."""
    from contextlib import asynccontextmanager

    from desk.api import public as pub

    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    @asynccontextmanager
    async def _session():
        async with sm() as s:
            yield s

    monkeypatch.setattr(pub, "session", _session)
    monkeypatch.setattr(pub, "STREAM_IDLE_S", 0.1)
    team = await _team(ctx, db)
    t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(81, "goes private live", body="b"))
    await db.commit()
    head = (await EventLog.head(db)).index

    calls = {"n": 0}

    class Req:
        headers: dict = {}

        async def is_disconnected(self):
            calls["n"] += 1
            return calls["n"] > 2  # one read before the wait, one after the wake-up, then gone

    who = type("W", (), {"principal": authz.ANON})()
    resp = await pub.events_stream(ctx, Req(), who, since=None)
    gen = resp.body_iterator
    got: list[dict] = []

    async def consume():
        async for item in gen:
            got.append(item)

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)  # the stream is now waiting on its wake-up
    # three live events: a public row on a ticket that is private now, an admin row, and ticket.sealed
    await tsvc.set_facts(ctx, db, team, t, {"visibility": "private"})
    await users.create_user(ctx, db, "test", "late@xe.network", "Late", ["reviewer"])
    await db.commit()
    await asyncio.wait_for(task, 5)
    served = [json.loads(i["data"]) for i in got if i.get("event") == "entry"]
    assert all(e["index"] > head for e in served)
    assert [e["kind"] for e in served] == ["ticket.sealed"]
    assert all(not e["kind"].startswith(("user.", "team.", "token.")) for e in served)
    # the same rows through the other public read paths agree
    assert [e.kind for e in await EventLog.since(db, head, 100)] == ["ticket.sealed"]
    assert pub._event_id("--") is None and pub._event_id("²") is None and pub._event_id("7") == 7


async def test_held_facts_stay_out_of_public_payloads(ctx, db):
    from desk.log import public_payload

    assert public_payload("ticket.award", {"ticket": "XE-0001", "award_xe": 5, "tier": "high"}) == {
        "ticket": "XE-0001", "award_xe": 5,
    }  # XE-0604
    assert public_payload("ticket.status", {"via": "internal:xeprotocol/core#12", "reason": "x"}) == {
        "via": "internal",
    }  # XE-0612
    predates = public_payload("ticket.internal_predates", {"ticket": "x", "internal_ref": "#9"})
    assert "internal_ref" not in predates
    adopted = public_payload("proposal.adopted", {"ticket": "x", "reason": "it is High"})
    assert "reason" not in adopted  # XE-0768
    # fill never names a held tier and never reaches past known placeholders (XE-0733, XE-0956)
    team = await _team(ctx, db)
    t = await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "high"})
    assert thread.fill(ctx, "Tier: {tier}.", t) == "Tier: ."
    assert thread.fill(ctx, "{ticket_url.__class__} {0} {reason!r} {tier:>5} {unknown}", t) == (
        "{ticket_url.__class__} {0} {reason!r} {tier:>5} {unknown}"
    )
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, team, t, st)
    assert thread.fill(ctx, "Tier: {tier}.", t) == "Tier: High."
    # the team-only axes and the assessment go with notes access, not with being a token (XE-1560, XE-0696)
    linker = await _agent(ctx, db, team.user, scopes=("write:patch-refs",))
    assert not tsvc.sees_assessment(linker) and not authz.can(linker, "read:notes")
    reader = await _agent(ctx, db, team.user, scopes=("read:public",))
    assert tsvc.sees_assessment(reader)


async def test_text_is_cleaned_and_chat_closes_stay_in_their_lane(ctx, db):
    team = await _team(ctx, db)
    title, body = "nul\x00 in\nthe title", "body\x00 here\x07"
    spec = tsvc.NewTicket(kind="bounty", title=title, body=body, source="web")
    t = await tsvc.create(ctx, db, team.actor, spec)
    assert t.title == "nul in the title" and t.body == "body here"  # XE-1426
    assert tsvc.clean_text("a\udc80b") == "ab"
    # a Discord /close is for questions; an accepted report is closed from the desk (XE-0690, XE-0805)
    for st in ("triaging", "accepted"):
        await tsvc.set_status(ctx, db, team, t, st)
    with pytest.raises(HTTPException) as e:
        await channels.close_from_channel(ctx, db, t, user_id="1", reason="")
    assert e.value.status_code == 409 and t.status == "accepted"
    # the awarded record does not walk back (XE-0789), and an award needs a tier (XE-0470)
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, team, t, 1_000_000)
    assert e.value.status_code == 409 and "tier" in e.value.detail
    await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "minor"})
    await tsvc.set_award(ctx, db, team, t, 1_000_000)
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, team, t, tsvc.AWARD_MAX + 1)
    assert e.value.status_code == 400  # XE-0973
    with pytest.raises(HTTPException) as e:
        await tsvc.set_facts(ctx, db, team, t, {"visibility": None})
    assert e.value.status_code == 400
    await tsvc.set_status(ctx, db, team, t, "patched")
    await tsvc.set_award(ctx, db, team, t, None, approve=True)
    # the tier moves after approval: approval is taken back and the amount is re-checked (XE-0890)
    diff = await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "high"})
    assert t.award_approved_at is None and diff["award_approved"] == {"from": True, "to": False}
    await tsvc.set_award(ctx, db, team, t, 8_000_000_000)  # within 2x high
    await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "minor"})
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, team, t, None, approve=True)  # 8,000 XE is over 2x minor
    assert e.value.status_code == 400
    await tsvc.set_award(ctx, db, team, t, 1_000_000_000)
    await tsvc.set_award(ctx, db, team, t, None, approve=True)
    await tsvc.set_status(ctx, db, team, t, "awarded")
    with pytest.raises(HTTPException) as e:
        await tsvc.set_status(ctx, db, team, t, "triaging")
    assert e.value.status_code == 409


async def test_severity_sort(ctx, db):
    p = await _team(ctx, db)
    a = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="minor", source="web"))
    b = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="severe", source="web"))
    c = await tsvc.create(
        ctx,
        db,
        p.actor,
        tsvc.NewTicket(kind="bounty", title="claimed high", source="web", claimed_tier="high"),
    )
    await tsvc.set_facts(ctx, db, p, a, {"assessed_tier": "minor"})
    await tsvc.set_facts(ctx, db, p, b, {"assessed_tier": "severe"})
    rows = await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters())
    assert [r.id for r in rows] == [b.id, a.id, c.id]
    # the public is shown the claim while the assessment is held, and sorts and filters on that
    anon = authz.ANON
    rows = await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters())
    assert [r.id for r in rows] == [c.id, a.id, b.id]
    assert [r.id for r in await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters(tier="severe"))] == [b.id]
    assert await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(tier="severe")) == []
    assert [r.id for r in await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(tier="high"))] == [c.id]
    await tsvc.set_facts(ctx, db, p, b, {"verdict": "valid", "mainnet_gate": "later", "internal_ref": "#9"})
    assert await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(verdict="valid")) == []
    with pytest.raises(HTTPException) as e:  # a team-only axis is refused, not quietly dropped (XE-1560)
        await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(status="all", gate="later"))
    assert e.value.status_code == 403
    assert await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(q="#9")) == []
    assert [r.id for r in await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters(q="#9"))] == [b.id]
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, p, b, st)
    # patched is no longer "open"; across the whole desk the assessment now shows and sorts
    rows = await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(status="all", tier="severe"))
    assert [r.id for r in rows] == [b.id]
    everything = await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(status="all"))
    assert [r.id for r in everything] == [b.id, c.id, a.id]
    assert [r.id for r in await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters())] == [c.id, a.id]


# ---- proposals --------------------------------------------------------------------------------------


async def test_agent_proposes_human_adopts(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    with pytest.raises(HTTPException):
        await psvc.propose(ctx, db, p, t, "verdict", "valid", "people set facts directly")
    # a status the desk could never apply is refused when proposed, not when a person clicks adopt (XE-1054)
    for bad in (
        {"status": "closed", "closed_reason": "by-design"},
        {"status": "closed"},
        {"status": "triaging", "closed_reason": "invalid"},
        "resolved",
        42,
    ):
        with pytest.raises(HTTPException) as e:
            await psvc.propose(ctx, db, agent, t, "status", bad, "no")
        assert e.value.status_code == 400, bad
    pr1 = await psvc.propose(ctx, db, agent, t, "verdict", "valid", "reproduced")
    pr2 = await psvc.propose(ctx, db, agent, t, "assessed_tier", "high", "targeted DoS")
    pr3 = await psvc.propose(ctx, db, agent, t, "reply_draft", "Thanks, reproduced. See {ticket_url}.", "")
    out = await psvc.decide(ctx, db, p, pr1, True)
    assert out["diff"]["verdict"]["to"] == "valid" and t.verdict == "valid"
    with pytest.raises(HTTPException) as e:
        await psvc.decide(ctx, db, p, pr2, True)  # reviewer lacks the tier role
    assert e.value.status_code == 403 and pr2.state == "pending"
    out = await psvc.decide(ctx, db, p, pr3, True)
    url = tsvc.ticket_url(ctx, t)
    assert out["reply_draft"] == f"Thanks, reproduced. See {url}." and t.status == "new"
    # the draft is kept on the ticket, for the team only, until a reply goes out
    assert t.draft == out["reply_draft"] and tsvc.to_dict(ctx, t, p)["draft"] == t.draft
    assert "draft" not in tsvc.to_dict(ctx, t, authz.ANON)
    assert (await db.execute(select(Reply))).scalars().all() == []
    await thread.add_reply(ctx, db, p, t, "Thanks, reproduced.")
    assert t.draft == ""
    with pytest.raises(HTTPException):
        await psvc.decide(ctx, db, agent, pr2, False)
    # a repeat proposal supersedes the pending one
    pr4 = await psvc.propose(ctx, db, agent, t, "assessed_tier", "medium", "second look")
    await db.refresh(pr2)
    assert pr2.state == "superseded" and pr4.state == "pending"
    note = await thread.add_note(ctx, db, agent, t, "internal")
    assert note.author == f"token:{agent.token.id}"
    pub = await EventLog.page(db, 0, 100, ref=t.id, public_only=True)
    assert not any("Thanks, reproduced" in str(e.payload) for e in pub), "drafts never land in the public log"


async def test_plain_acknowledgements_send_on_adopt_and_the_rest_wait(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)

    def mk(title):
        return tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=title, source="web"))

    plain = await mk("plain")
    tiered = await mk("names a tier")
    closing = await mk("closes too")
    told = await mk("already written to")
    ack = "Thanks for the report. We have read it against the code and it is being handled; see {ticket_url}."
    d_plain = await psvc.propose(ctx, db, agent, plain, "reply_draft", ack, "acknowledgement")
    v_plain = await psvc.propose(ctx, db, agent, plain, "verdict", "valid", "reproduced")
    d_tier = await psvc.propose(ctx, db, agent, tiered, "reply_draft", "Thanks. We rate this High.", "")
    d_close = await psvc.propose(ctx, db, agent, closing, "reply_draft", "Thanks, we have read it.", "")
    s_close = await psvc.propose(
        ctx, db, agent, closing, "status", {"status": "closed", "closed_reason": "invalid"}, "no"
    )
    d_told = await psvc.propose(ctx, db, agent, told, "reply_draft", "Thanks, we have read it.", "")
    await thread.add_reply(ctx, db, p, told, "Already answered by hand.")

    # the text rule, on its own
    rr = thread.review_reason
    assert rr(ctx, thread.fill(ctx, ack, plain), plain) is None
    assert rr(ctx, "Thanks. We rate this High.", plain) == "names a tier"
    assert rr(ctx, f"Thanks. See {tsvc.ticket_url(ctx, plain)} and {plain.id}.", plain) is None
    assert rr(ctx, "Thanks. Tracked as XE-9999.", plain) == "names another ticket"
    assert rr(ctx, "Thanks. See https://example.com/x.", plain) == "has a link"
    assert rr(ctx, "Thanks. Fixed in 2 days.", plain) == "has a number"
    assert rr(ctx, "Thanks. The award follows the fix.", plain) == "mentions payment"
    # the programme's stock lines pass whatever words they carry; the rest is still checked
    stock = (
        "Thanks for the report. We have read it against the code and it is being handled alongside"
        " related multisig work. This ticket is updated when the fix lands, and the assessment and any"
        " award follow the fix."
    )
    assert ctx.config.plain_phrases and rr(ctx, stock, plain) is None
    assert rr(ctx, stock + " The award will be 500 XE.", plain) == "has a number"
    assert rr(ctx, stock + " We will pay it on Friday.", plain) == "mentions payment"
    design = (
        "Thanks for the report. We read it against the code: the behaviour is as designed today, and"
        " the design question it raises is with the team. This ticket is updated when there is a decision."
    )
    assert rr(ctx, design, plain) is None
    assert rr(ctx, "Thanks. Closing as invalid.", plain) == "explains a closure"
    assert rr(ctx, "Thanks. The gap is in `VerifyMultisig`.", plain) == "names code or a path"
    assert rr(ctx, "Thanks. The gap is in net/sync.", plain) == "names code or a path"
    assert rr(ctx, "x" * 301, plain).startswith("over ")

    # the ticket page's single adopt never sends, whatever the text
    out = await psvc.decide(ctx, db, p, d_plain, True)
    assert "sent" not in out and plain.draft == out["reply_draft"]
    assert (await db.execute(select(Reply).where(Reply.ticket_id == plain.id))).scalars().all() == []
    d_plain2 = await psvc.propose(ctx, db, agent, plain, "reply_draft", ack, "again")

    # the triage page's batch: the plain one goes out; the status is adopted before the draft on the
    # closing ticket, so that draft waits; a tier in the text waits; a reporter written to since waits
    ids = [d_plain2.id, v_plain.id, d_tier.id, d_close.id, s_close.id, d_told.id]
    out = await psvc.decide_many(ctx, db, p, ids, [], send_plain=True)
    assert out["skipped"] == []
    by = {d["proposal"]: d for d in out["decided"]}
    sent = by[d_plain2.id]
    assert sent["sent"] and sent["reply_text"].endswith(tsvc.ticket_url(ctx, plain) + ".")
    assert by[d_tier.id]["review"] == "names a tier" and "sent" not in by[d_tier.id]
    assert by[d_close.id]["review"] == "the ticket is closed" and "sent" not in by[d_close.id]
    assert by[d_told.id]["review"] == "the reporter has been written to since"
    await db.refresh(plain)
    await db.refresh(tiered)
    await db.refresh(closing)
    replies = (await db.execute(select(Reply).where(Reply.ticket_id == plain.id))).scalars().all()
    assert len(replies) == 1 and replies[0].author_id == p.user.id and plain.draft == ""
    assert tiered.draft == "Thanks. We rate this High." and closing.draft == "Thanks, we have read it."
    assert closing.status == "closed"
    # a draft that rides with a pending closure waits even when the closure is not in the same batch
    again = await mk("closure pending elsewhere")
    d_again = await psvc.propose(ctx, db, agent, again, "reply_draft", "Thanks, we have read it.", "")
    await psvc.propose(ctx, db, agent, again, "duplicate_of", plain.id, "same")
    assert psvc.send_review(ctx, await psvc.pending_for(db, again), d_again, again) == "goes with a closure"


async def test_a_family_of_duplicates_closes_in_one_ruling(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    canon = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="first", source="web"))
    dups = [
        await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=f"again {i}", source="web"))
        for i in range(3)
    ]
    # the agent proposes the usual four on two of them, only duplicate_of on the third
    for t in dups[:2]:
        await psvc.propose(ctx, db, agent, t, "duplicate_of", canon.id, "same defect, filed later")
        await psvc.propose(ctx, db, agent, t, "verdict", "duplicate", "same defect")
        closing = {"status": "closed", "closed_reason": "duplicate"}
        await psvc.propose(ctx, db, agent, t, "status", closing, "dup")
        await psvc.propose(ctx, db, agent, t, "reply_draft", "Same as {duplicate_url}.", "")
    await psvc.propose(ctx, db, agent, dups[2], "duplicate_of", canon.id, "same defect, filed later")
    # an unrelated proposal and a proposal naming another canonical are not part of the family
    other = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="other", source="web"))
    await psvc.propose(ctx, db, agent, other, "duplicate_of", dups[0].id, "a different family")
    fam = await psvc.pending_duplicates_of(db, canon.id)
    assert [t.id for t, _ in fam] == sorted(t.id for t in dups)

    with pytest.raises(HTTPException):
        await psvc.close_duplicates(ctx, db, agent, canon)  # a person rules, never a token
    out = await psvc.close_duplicates(ctx, db, p, canon)
    assert [d["ticket"] for d in out["closed"]] == sorted(t.id for t in dups) and out["skipped"] == []
    for t in dups:
        await db.refresh(t)
        assert (t.status, t.closed_reason, t.duplicate_of) == ("closed", "duplicate", canon.id)
        assert t.verdict == "duplicate"
        assert t.draft == ""  # the adopted draft was replaced by the sent reply
    ids = [t.id for t in dups]
    replies = (await db.execute(select(Reply).where(Reply.ticket_id.in_(ids)))).scalars().all()
    assert len(replies) == 3 and all(canon.id in r.body and r.author_id == p.user.id for r in replies)
    # every proposal in the family is decided; the one naming another canonical still waits
    states = Counter(pr.state for pr in (await db.execute(select(Proposal))).scalars().all())
    assert states == {"adopted": 9, "pending": 1}
    assert await psvc.pending_duplicates_of(db, canon.id) == []
    # the log shows the ruling as the person's, hop by hop, with the family named
    evs = await EventLog.page(db, 0, 200, ref=dups[2].id)
    assert any(e.kind == "ticket.status" and e.payload.get("via") == f"family:{canon.id}" for e in evs)
    assert all(e.actor == p.actor for e in evs if e.kind.startswith("ticket."))


async def test_a_marked_duplicate_with_the_close_still_pending_is_part_of_the_family(ctx, db):
    # the mark was adopted on its own (or set by hand); the status chip is all that is left on the row.
    # It still belongs to the duplicates view and to the family's one-click ruling.
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    canon = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="first", source="web"))
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="again", source="web"))
    mark = await psvc.propose(ctx, db, agent, t, "duplicate_of", canon.id, "same defect, filed later")
    closing = {"status": "closed", "closed_reason": "duplicate"}
    s = await psvc.propose(ctx, db, agent, t, "status", closing, "dup")
    await psvc.decide(ctx, db, p, mark, True)
    assert t.duplicate_of == canon.id and s.state == "pending"
    assert psvc.triage_views([s]) == {"duplicates"}
    row = psvc.TriageRow(t, [s])
    assert row.duplicate_of == canon.id
    fam = await psvc.pending_duplicates_of(db, canon.id)
    assert [(o.id, pr) for o, pr in fam] == [(t.id, None)]
    out = await psvc.close_duplicates(ctx, db, p, canon)
    assert [d["ticket"] for d in out["closed"]] == [t.id] and out["skipped"] == []
    await db.refresh(t)
    await db.refresh(s)
    assert (t.status, t.closed_reason, t.verdict, s.state) == ("closed", "duplicate", "duplicate", "adopted")
    replies = (await db.execute(select(Reply).where(Reply.ticket_id == t.id))).scalars().all()
    assert len(replies) == 1 and canon.id in replies[0].body
    assert await psvc.pending_duplicates_of(db, canon.id) == []


async def test_a_family_with_a_paid_member_closes_the_rest(ctx, db):
    # XE-0862: a member the state machine will not close (paid is terminal) used to raise MissingGreenlet
    # on the way into `skipped`, because the row was expired by the savepoint rollback before its id was read
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    canon = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="first", source="web"))
    a = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="a", source="web"))
    b = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="b", source="web"))
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, p, b, st, force=True)
    for t in (a, b):
        await psvc.propose(ctx, db, agent, t, "duplicate_of", canon.id, "same defect, filed later")
    a_id, b_id = a.id, b.id  # the rollback expires b; its attributes need a refresh before they are read
    out = await psvc.close_duplicates(ctx, db, p, canon)
    assert [d["ticket"] for d in out["closed"]] == [a_id]
    assert [s["ticket"] for s in out["skipped"]] == [b_id] and "paid" in out["skipped"][0]["why"]
    await db.refresh(a)
    await db.refresh(b)
    assert (a.status, a.duplicate_of) == ("closed", canon.id)
    assert (b.status, b.duplicate_of) == ("paid", None), "the refused member is left exactly as it was"


async def test_bulk_decisions_skip_the_refused_and_keep_the_rest(ctx, db):
    # XE-0872: one refusal in a batch stopped the batch; now each decision is its own savepoint
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    a = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="a", source="web"))
    b = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="b", source="web"))
    c = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="c", source="web"))
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, p, b, st, force=True)
    ok1 = await psvc.propose(ctx, db, agent, a, "verdict", "valid", "reproduced")
    bad_path = await psvc.propose(ctx, db, agent, b, "status", "fixing", "no path from paid")
    bad_role = await psvc.propose(ctx, db, agent, c, "assessed_tier", "high", "reviewer lacks tier")
    ok2 = await psvc.propose(ctx, db, agent, c, "verdict", "valid", "reproduced too")
    gone = await psvc.propose(ctx, db, agent, a, "effort_eng", "s", "to be rejected")
    with pytest.raises(HTTPException):
        await psvc.decide_many(ctx, db, agent, [ok1.id], [])  # a person rules, never a token
    bp, br, b_id, c_id = bad_path.id, bad_role.id, b.id, c.id  # read before the savepoints roll back
    out = await psvc.decide_many(ctx, db, p, [ok1.id, bp, br, ok2.id, 999_999], [gone.id])
    assert len(out["decided"]) == 3
    why = {s["proposal"]: s["why"] for s in out["skipped"]}
    assert set(why) == {bp, br, 999_999}
    assert "paid to fixing" in why[bp] and why[999_999] == "no such proposal"
    assert {s.get("ticket") for s in out["skipped"]} == {b_id, c_id, None}
    for pr in (ok1, bad_path, bad_role, ok2, gone):
        await db.refresh(pr)
    assert (ok1.state, ok2.state, gone.state) == ("adopted", "adopted", "rejected")
    assert (bad_path.state, bad_role.state) == ("pending", "pending")
    await db.refresh(a)
    await db.refresh(b)
    await db.refresh(c)
    assert (a.verdict, c.verdict, b.status, c.assessed_tier) == ("valid", "valid", "paid", None)
    # a second pass on the same ids finds them decided already
    again = await psvc.decide_many(ctx, db, p, [ok1.id], [gone.id])
    assert again["decided"] == [] and [s["why"] for s in again["skipped"]] == ["not pending", "not pending"]


async def test_triage_rows_sort_tickets_into_views(ctx, db):
    p = await _team(ctx, db, roles=("reviewer", "tier"))
    agent = await _agent(ctx, db, p.user)

    def mk(title, **kw):
        return tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=title, source="web", **kw))

    canon = await mk("canonical")
    dup = await mk("same again")
    closing = await mk("not a bug")
    finding = await mk("a real one")
    paid_reply = await mk("worth paying")
    await mk("nothing pending")  # stays off the page
    hidden = await mk("private pending", visibility="private")
    await tsvc.set_facts(ctx, db, p, finding, {"area": "sdk-docs-web"}, reason="t")
    await psvc.propose(ctx, db, agent, dup, "duplicate_of", canon.id, "same defect")
    closed = {"status": "closed", "closed_reason": "duplicate"}
    await psvc.propose(ctx, db, agent, dup, "status", closed, "dup")
    await psvc.propose(ctx, db, agent, dup, "verdict", "duplicate", "same defect")
    closed = {"status": "closed", "closed_reason": "invalid"}
    await psvc.propose(ctx, db, agent, closing, "status", closed, "no")
    await psvc.propose(ctx, db, agent, closing, "verdict", "invalid", "by design")
    await psvc.propose(ctx, db, agent, finding, "verdict", "valid", "reproduced")
    await psvc.propose(ctx, db, agent, finding, "assessed_tier", "high", "targeted DoS")
    await psvc.propose(ctx, db, agent, finding, "reply_draft", "Thanks, reproduced.", "")
    await tsvc.set_facts(ctx, db, p, paid_reply, {"assessed_tier": "minor"}, reason="t")
    await psvc.propose(ctx, db, agent, paid_reply, "award_xe", 100, "Bottom of the band, reason long enough.")
    await psvc.propose(ctx, db, agent, hidden, "verdict", "valid", "reproduced")
    await thread.add_note(ctx, db, agent, finding, "**Claim.** Crashes the node with one packet.\n\nMore.")
    await thread.add_note(ctx, db, agent, finding, "**Claim.** Second look: still crashes.")

    rows = await psvc.triage_rows(db, ctx.config, p)
    by = {r.ticket.id: r for r in rows}
    assert set(by) == {dup.id, closing.id, finding.id, paid_reply.id, hidden.id}
    assert by[dup.id].views == {"duplicates"} and by[dup.id].canonical.id == canon.id
    assert by[closing.id].views == {"closures"}
    assert by[finding.id].views == {"assessments", "replies"} and by[finding.id].tier == "high"
    assert by[paid_reply.id].views == {"awards"} and by[paid_reply.id].tier == "minor"
    # most severe first, by the proposed tier; the agent's latest note rides along, first line only
    assert rows[0].ticket.id == finding.id
    assert psvc.note_excerpt(by[finding.id].note) == "Second look: still crashes."
    assert by[dup.id].note is None
    # the views and the other filters narrow; the counts do not
    assert [r.ticket.id for r in await psvc.triage_rows(db, ctx.config, p, view="duplicates")] == [dup.id]
    assert [r.ticket.id for r in await psvc.triage_rows(db, ctx.config, p, view="replies")] == [finding.id]
    by_area = await psvc.triage_rows(db, ctx.config, p, area="sdk-docs-web")
    assert [r.ticket.id for r in by_area] == [finding.id]
    assert [r.ticket.id for r in await psvc.triage_rows(db, ctx.config, p, tier="minor")] == [paid_reply.id]
    counts = await psvc.triage_counts(db, p)
    assert counts["all"] == 5 and counts["proposals"] == 10
    assert (counts["duplicates"], counts["closures"], counts["assessments"]) == (1, 1, 2)
    assert (counts["awards"], counts["replies"]) == (1, 1)
    # a viewer without read:private sees neither the private row nor its count
    public_eyes = await _agent(ctx, db, p.user, scopes=("read:public",))
    assert hidden.id not in {r.ticket.id for r in await psvc.triage_rows(db, ctx.config, public_eyes)}
    assert (await psvc.triage_counts(db, public_eyes))["all"] == 4
    # the class: every report on the same engineering ticket rides on the row, the private one included
    for t in (finding, hidden, canon):
        await tsvc.set_facts(ctx, db, p, t, {"internal_ref": "#1090"}, reason="one class")
    klass = await tsvc.same_class(db, p, {"#1090", ""})
    assert [o.id for o in klass["#1090"]] == sorted([finding.id, hidden.id, canon.id]) and "" not in klass
    public_view = await tsvc.same_class(db, public_eyes, {"#1090"})
    assert [o.id for o in public_view["#1090"]] == sorted([finding.id, canon.id])
    rows = {r.ticket.id: r for r in await psvc.triage_rows(db, ctx.config, p)}
    assert {o.id for o in rows[finding.id].klass} == {hidden.id, canon.id}  # not its own sibling
    assert rows[dup.id].klass == []


def test_status_path_walks_forward_edges_only():
    assert tsvc.status_path("bounty", "new", "accepted") == ["triaging", "accepted"]
    assert tsvc.status_path("bounty", "new", "patched") == ["triaging", "accepted", "patched"]
    assert tsvc.status_path("bounty", "new", "closed") == ["closed"]
    assert tsvc.status_path("bounty", "new", "new") == []
    assert tsvc.status_path("bounty", "paid", "fixing") is None
    # awarded is a terminal: no walking through it to paid
    assert tsvc.status_path("bounty", "patched", "paid") is None
    # closed is a terminal too: new → closed → triaging is not a path, but new → triaging is
    assert tsvc.status_path("bounty", "closed", "accepted") == ["triaging", "accepted"]
    assert tsvc.status_path("support", "new", "needs-info") == ["triaging", "needs-info"]
    assert tsvc.status_path("support", "new", "accepted") is None


async def test_adopting_a_far_status_walks_the_path(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    # new → accepted, via triaging: two status events, one via
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="a", source="web"))
    pr = await psvc.propose(ctx, db, agent, t, "status", "accepted", "reproduced and in scope")
    out = await psvc.decide(ctx, db, p, pr, True)
    assert out["status"] == "accepted" and out["path"] == ["triaging", "accepted"]
    assert t.status == "accepted"
    evs = await EventLog.page(db, 0, 100, ref=t.id, descending=False)
    moves = [(e.payload["from"], e.payload["to"]) for e in evs if e.kind == "ticket.status"]
    assert moves == [("new", "triaging"), ("triaging", "accepted")]
    assert {e.payload["via"] for e in evs if e.kind == "ticket.status"} == {f"proposal:{pr.id}"}
    # new → patched: three hops
    t2 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="b", source="web"))
    pr2 = await psvc.propose(ctx, db, agent, t2, "status", "patched", "fix landed")
    out = await psvc.decide(ctx, db, p, pr2, True)
    assert out["path"] == ["triaging", "accepted", "patched"] and t2.status == "patched"
    # paid → fixing: no path, 409, nothing moves, proposal stays pending
    t3 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="c", source="web"))
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, p, t3, st, force=True)
    pr3 = await psvc.propose(ctx, db, agent, t3, "status", "fixing", "regressed")
    with pytest.raises(HTTPException) as e:
        await psvc.decide(ctx, db, p, pr3, True)
    assert e.value.status_code == 409 and "paid to fixing" in e.value.detail
    assert t3.status == "paid" and pr3.state == "pending"
    # closed as duplicate from new: one hop, with the reason
    t4 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="d", source="web"))
    await tsvc.set_facts(ctx, db, p, t4, {"duplicate_of": t.id})
    pr4 = await psvc.propose(
        ctx, db, agent, t4, "status", {"status": "closed", "closed_reason": "duplicate"}, "same as a"
    )
    out = await psvc.decide(ctx, db, p, pr4, True)
    assert out["path"] == ["closed"] and t4.status == "closed" and t4.closed_reason == "duplicate"
    # the current status is a no-op, as before
    pr5 = await psvc.propose(ctx, db, agent, t2, "status", "patched", "already there")
    moves = sum(e.kind == "ticket.status" for e in await EventLog.page(db, 0, 100, ref=t2.id))
    out = await psvc.decide(ctx, db, p, pr5, True)
    assert out["path"] == [] and t2.status == "patched"
    assert sum(e.kind == "ticket.status" for e in await EventLog.page(db, 0, 100, ref=t2.id)) == moves


async def test_agent_proposes_an_award_and_a_treasurer_sets_it(ctx, db):
    reviewer = await _team(ctx, db, roles=("reviewer", "tier"))
    agent = await _agent(ctx, db, reviewer.user)
    t = await tsvc.create(ctx, db, reviewer.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    await tsvc.set_facts(ctx, db, reviewer, t, {"assessed_tier": "medium"}, reason="t")
    for bad, why in ((2500.5, "float"), ("2500", "string"), (-1, "negative"), (True, "bool"), (5001, "over 2x ceiling")):
        with pytest.raises(HTTPException) as e:
            await psvc.propose(ctx, db, agent, t, "award_xe", bad, "a reason long enough to pass the check")
        assert e.value.status_code == 400, why
    with pytest.raises(HTTPException):
        await psvc.propose(ctx, db, agent, t, "award_xe", 2000, "short")
    pr = await psvc.propose(ctx, db, agent, t, "award_xe", 2000, "Top of the band: precise, right fix suggested.")
    with pytest.raises(HTTPException) as e:
        await psvc.decide(ctx, db, reviewer, pr, True)  # setting an award needs the treasurer role
    assert e.value.status_code == 403 and pr.state == "pending" and t.award_xe is None
    treasurer = await _team(ctx, db, roles=("reviewer", "treasurer"))
    out = await psvc.decide(ctx, db, treasurer, pr, True)
    assert out["award_xe"] == 2_000_000_000 and t.award_xe == 2_000_000_000
    assert t.award_approved_at is None, "adopting sets the amount; approval is a separate act"
    due = await tsvc.awards_due(db, ctx.config, treasurer)
    assert t.id not in [d.id for d in due], "a new ticket is not yet due; it has to be accepted first"
    await tsvc.set_status(ctx, db, treasurer, t, "triaging")
    await tsvc.set_status(ctx, db, treasurer, t, "accepted")
    assert t.id in [d.id for d in await tsvc.awards_due(db, ctx.config, treasurer)]
    # approval waits for the fix: not from accepted
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, treasurer, t, None, approve=True)
    assert e.value.status_code == 409 and "patched" in e.value.detail and t.award_approved_at is None
    assert tsvc.award_approvable(t) is not None
    await tsvc.set_status(ctx, db, treasurer, t, "patched")
    assert tsvc.award_approvable(t) is None
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=True)
    assert t.award_approved_at is not None
    assert t.id not in [d.id for d in await tsvc.awards_due(db, ctx.config, treasurer)]
    # an approved amount cannot be changed, but approval can be taken back and the amount stays
    with pytest.raises(HTTPException) as e:
        t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
        await tsvc.set_award(ctx, db, treasurer, t, 1_000_000_000)
    assert e.value.status_code == 409
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=False)
    assert t.award_approved_at is None and t.award_approved_by is None and t.award_xe == 2_000_000_000
    assert t.id in [d.id for d in await tsvc.awards_due(db, ctx.config, treasurer)]
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=None)  # None leaves approval alone
    assert t.award_approved_at is None
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=True)
    await tsvc.set_status(ctx, db, treasurer, t, "awarded")
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, treasurer, t, None, approve=False)  # awarded: the award stands
    assert e.value.status_code == 409 and t.award_approved_at is not None
    grouped = await psvc.pending_field_for(db, [t.id], "award_xe")
    assert grouped == {}  # adopted, so no longer pending


async def test_a_member_is_renamed_and_future_replies_carry_it(ctx, db):
    team = await _team(ctx, db)
    spec = tsvc.NewTicket(kind="bounty", title="Renaming test", body="b" * 50)
    t = await tsvc.create(ctx, db, "desk", spec)
    r1 = await thread.add_reply(ctx, db, team, t, "First reply, under the old name.")
    await users.set_name(ctx, db, "cli", team.user, "  Joseph   Denne ")
    assert team.user.name == "Joseph Denne"
    r2 = await thread.add_reply(ctx, db, team, t, "Second reply, under the new name.")
    assert r1.author_name == "Lead" and r2.author_name == "Joseph Denne"
    with pytest.raises(HTTPException):
        await users.set_name(ctx, db, "cli", team.user, "   ")
    # email: must look like one and be free
    await users.set_email(ctx, db, "cli", team.user, " Joseph@XE.network ")
    assert team.user.email == "joseph@xe.network"
    other = await users.create_user(ctx, db, "test", "other@xe.network", "Other", ["reviewer"])
    with pytest.raises(HTTPException):
        await users.set_email(ctx, db, "cli", other, "joseph@xe.network")
    with pytest.raises(HTTPException):
        await users.set_email(ctx, db, "cli", other, "not-an-address")


# ---- github sync ------------------------------------------------------------------------------------


def _issue(number, title, body="", state="open", login="ada", **kw):
    return {
        "number": number, "title": title, "body": body, "state": state, "labels": [], "comments": 0,
        "html_url": f"https://github.com/xeprotocol/xe/issues/{number}", "created_at": "2026-10-20T10:00:00Z",
        "updated_at": "2026-10-20T10:00:00Z", "user": {"login": login, "id": 7}, **kw,
    }


async def test_internal_tracker_moves_a_new_ticket_through_triaging(ctx, db):
    t, created = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(63, "Explorer search bar"))
    assert created and t.status == "new"
    # the tracker names it while open: new -> triaging -> accepted, not a forbidden jump
    stats = await sync.link_internal_issue(ctx, db, _issue(1068, "security: bounty bundle xe#63"))
    assert stats["linked"] == 1 and stats["moved"] == 1
    assert t.status == "accepted" and t.internal_ref == "#1068"
    # closed as completed: patched, and into the outbox
    stats = await sync.link_internal_issue(
        ctx, db, _issue(1068, "security: bounty bundle xe#63", state="closed", state_reason="completed")
    )
    assert stats["moved"] == 1 and t.status == "patched"
    # a ticket past the tracker's reach is left where it is
    t2, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(64, "Another report"))
    team = await _team(ctx, db)
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, team, t2, st, force=True)
    done = _issue(1069, "bundle xe#64", state="closed", state_reason="completed")
    stats = await sync.link_internal_issue(ctx, db, done)
    assert stats["moved"] == 0 and t2.status == "paid"
    # importing the same issue again finds the ticket; nothing is created twice
    await db.commit()
    other = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(63, "Explorer search bar"))
    assert other[0].id == t.id and other[1] is False


async def test_internal_tracker_names_desk_filed_reports_by_id(ctx, db):
    team = await _team(ctx, db)
    new = lambda title: tsvc.NewTicket(kind="bounty", title=title, source="web")  # noqa: E731
    web = await tsvc.create(ctx, db, team.actor, new("filed here"))
    dup = await tsvc.create(ctx, db, team.actor, new("again"))
    gh_t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(65, "filed on github"))
    # one internal ticket covers a GitHub report by number and two desk reports by id, one in lower case
    body = f"Covers xe#65, {web.id} and {dup.id.lower()}. Root cause in net/check."
    stats = await sync.link_internal_issue(ctx, db, _issue(1070, "security: netcheck bundle", body=body))
    assert stats["tagged"] == 3 and stats["linked"] == 3 and stats["moved"] == 3
    for t in (web, dup, gh_t):
        assert t.status == "accepted" and t.internal_ref == "#1070"
    # naming the same ticket both ways is one ticket, not two
    stats = await sync.link_internal_issue(ctx, db, _issue(1071, f"bundle xe#65 {gh_t.id}"))
    assert stats["tagged"] == 1 and stats["noted"] == 1  # already #1070; said once, not overwritten
    assert gh_t.internal_ref == "#1070"
    # the fix ships: closing the internal ticket patches every report linked to it, including one whose
    # mention was edited out of the body since; the link made earlier is what counts
    edited = f"Covers xe#65 and {dup.id}. Root cause in net/check."
    done = _issue(1070, "security: netcheck bundle", body=edited, state="closed", state_reason="completed")
    stats = await sync.link_internal_issue(ctx, db, done)
    assert stats["tagged"] == 3 and stats["moved"] == 3
    assert {t.status for t in (web, dup, gh_t)} == {"patched"}


def _pull(number, title, body="", state="open", merged=False, login="grace", association="MEMBER"):
    return {
        "number": number, "title": title, "body": body, "state": state,
        "merged_at": "2026-10-21T10:00:00Z" if merged else None,
        "html_url": f"https://github.com/xeprotocol/xe/pull/{number}",
        "user": {"login": login, "id": 9}, "author_association": association,
    }


async def test_a_fixing_pull_moves_the_ticket_and_a_mention_only_links(ctx, db):
    repo = "xeprotocol/xe"
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(70, "Vote replay"))
    # "fixes #70" while open: new -> triaging -> accepted -> fixing, every hop logged
    assert await sync.link_pull(ctx, db, repo, _pull(80, "Reject replayed votes", "Fixes #70")) == 1
    assert t.status == "fixing"
    evs = await EventLog.page(db, 0, 100, ref=t.id, descending=False)
    moves = [(e.payload["from"], e.payload["to"]) for e in evs if e.kind == "ticket.status"]
    assert moves == [("new", "triaging"), ("triaging", "accepted"), ("accepted", "fixing")]
    assert {e.payload["via"] for e in evs if e.kind == "ticket.status"} == {f"github:{repo}#80"}
    # the same PR seen again (webhook "synchronize"): nothing new, nothing moved
    assert await sync.link_pull(ctx, db, repo, _pull(80, "Reject replayed votes", "Fixes #70")) == 0
    assert t.status == "fixing"
    # merged: patched, and so into the outbox
    await sync.link_pull(ctx, db, repo, _pull(80, "Reject replayed votes", "Fixes #70", state="closed", merged=True))
    assert t.status == "patched"
    assert t.id in [x.id for x in await tsvc.outbox(db, ctx.config, await _team(ctx, db))]
    # a bare mention links but does not move
    t2, _ = await sync.upsert_issue(ctx, db, repo, _issue(71, "Related nit"))
    assert await sync.link_pull(ctx, db, repo, _pull(81, "Tidy the voter", "see #71")) == 1
    assert t2.status == "new" and len(await thread.patches_for(db, t2)) == 1
    # a fixing PR closed unmerged drops the ticket back to accepted; a second live PR keeps it at fixing
    t3, _ = await sync.upsert_issue(ctx, db, repo, _issue(72, "Fork on equal height"))
    await sync.link_pull(ctx, db, repo, _pull(82, "First attempt", "Closes #72"))
    await sync.link_pull(ctx, db, repo, _pull(83, "Second attempt", "Closes #72"))
    assert t3.status == "fixing"
    await sync.link_pull(ctx, db, repo, _pull(82, "First attempt", "Closes #72", state="closed"))
    assert t3.status == "fixing"  # 83 is still open
    await sync.link_pull(ctx, db, repo, _pull(83, "Second attempt", "Closes #72", state="closed"))
    # back to where it was before any PR moved it (it was new: triaging), not a guessed accepted (XE-0634)
    assert t3.status == "triaging"
    # a stranger's open "fixes" PR holds nothing: the maintainer PR's unmerged close still returns the ticket
    t5, _ = await sync.upsert_issue(ctx, db, repo, _issue(73, "Stale peer list"))
    await sync.link_pull(ctx, db, repo, _pull(85, "Prune peers", "Fixes #73"))
    assert t5.status == "fixing"
    await sync.link_pull(ctx, db, repo, _pull(86, "junk", "fixes #73", login="rando", association="NONE"))
    assert t5.status == "fixing"
    await sync.link_pull(ctx, db, repo, _pull(85, "Prune peers", "Fixes #73", state="closed"))
    assert t5.status == "triaging"
    # past patched, GitHub never moves a ticket
    team = await _team(ctx, db, roles=("reviewer", "treasurer"))
    t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
    await tsvc.set_award(ctx, db, team, t, 1_000_000, approve=True)
    await tsvc.set_status(ctx, db, team, t, "awarded")
    await sync.link_pull(ctx, db, repo, _pull(84, "Follow-up", "Fixes #70", state="closed", merged=True))
    assert t.status == "awarded"


async def test_a_strangers_fork_pull_links_but_moves_nothing_until_merged(ctx, db):
    repo = "xeprotocol/xe"
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(90, "Panic on short key"))
    # anyone can open a fork PR saying "fixes #90": it is linked, with its author on show, and that is all
    fork = _pull(100, "fix: short key", "Fixes #90", login="mallory", association="NONE")
    assert await sync.link_pull(ctx, db, repo, fork) == 1
    assert t.status == "new"
    refs = await thread.patches_for(db, t)
    assert [(r.ref, r.author, r.state) for r in refs] == [("100", "mallory", "open")]
    # closing it unmerged changes nothing either; it never moved the ticket
    closed = _pull(100, "fix: short key", "Fixes #90", state="closed", login="mallory", association="NONE")
    await sync.link_pull(ctx, db, repo, closed)
    assert t.status == "new"
    # a maintainer's PR does move it, and remembers where from
    assert await sync.link_pull(ctx, db, repo, _pull(101, "fix(core): guard pk[:12]", "Fixes #90")) == 1
    assert t.status == "fixing"
    assert (await thread.patch_ref(db, t, repo, "101")).moved_from == "new"
    # the stranger's PR closed again while the maintainer's is open: still fixing
    await sync.link_pull(ctx, db, repo, closed)
    assert t.status == "fixing"
    # the maintainer abandons theirs: back to triaging (nothing returns to new), not parked at accepted
    await sync.link_pull(ctx, db, repo, _pull(101, "fix(core): guard pk[:12]", "Fixes #90", state="closed"))
    assert t.status == "triaging"
    # a merge is a maintainer's act whoever wrote the PR, so the stranger's PR merged does mean patched
    merged = _pull(100, "fix: short key", "Fixes #90", state="closed", merged=True, login="mallory",
                   association="NONE")
    await sync.link_pull(ctx, db, repo, merged)
    assert t.status == "patched"
    # the bot's own PRs count as the team's without an association
    ctx.settings.github_bot_login = "xe-desk-bot"
    t2, _ = await sync.upsert_issue(ctx, db, repo, _issue(91, "Another"))
    bot = _pull(102, "fix", "Fixes #91", login="xe-desk-bot", association="NONE")
    await sync.link_pull(ctx, db, repo, bot)
    assert t2.status == "fixing"


async def test_a_blocked_login_is_neither_linked_nor_mirrored(ctx, db):
    # XE-0128: an account that opened a patch two hours after someone else's report and posted its own
    # payout addresses in the thread. Blocked, its PRs do not link, its comments do not land, and what
    # arrived before the block comes off on the next sight of it.
    repo = "xeprotocol/xe"
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(215, "GET /frontiers does full-lattice work"))
    farm = _pull(217, "fix: page frontiers", "Fixes #215", login="farmer", association="NONE")
    planted = {"id": 69, "user": {"login": "farmer"}, "body": "Fix in #217. Beneficiary: 23bd7ef9..."}
    assert await sync.link_pull(ctx, db, repo, farm) == 1
    assert await sync.upsert_comment(ctx, db, t, planted) is True
    ctx.settings.github_blocked_logins = " Farmer ,other"  # case and spacing are not a way round it
    assert await sync.link_pull(ctx, db, repo, farm) == 0
    assert await thread.patches_for(db, t) == []
    assert await sync.upsert_comment(ctx, db, t, planted) is False
    msgs = await thread.messages_for(db, t)
    assert [m.body for m in msgs] == [sync.BLOCKED_MARK]
    # a new comment from the account never lands
    assert await sync.upsert_comment(ctx, db, t, {**planted, "id": 70}) is False
    assert len(await thread.messages_for(db, t)) == 1
    # a maintainer's PR against the same issue still does its work
    assert await sync.link_pull(ctx, db, repo, _pull(300, "fix(api): page frontiers", "Fixes #215")) == 1
    assert t.status == "fixing"
    ctx.settings.github_blocked_logins = ""


async def test_approved_awards_whose_ticket_has_not_caught_up_are_listed(ctx, db):
    team = await _team(ctx, db)
    t = await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, team, t, st)
    assert await tsvc.awards_approved_unawarded(db, ctx.config, team) == []
    t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
    await tsvc.set_award(ctx, db, team, t, 2_000_000, approve=True)
    rows = await tsvc.awards_approved_unawarded(db, ctx.config, team)
    assert [x.id for x in rows] == [t.id]
    assert tsvc.award_next_step(t)[1] == "awarded"  # public and patched: one click
    t.visibility = "private"
    assert tsvc.award_next_step(t)[1] is None and "disclose" in tsvc.award_next_step(t)[0]
    t.visibility = "public"
    await tsvc.set_status(ctx, db, team, t, "awarded")
    assert await tsvc.awards_approved_unawarded(db, ctx.config, team) == []
    assert tsvc.award_next_step(t) == ("done", None)


# ---- triage import ----------------------------------------------------------------------------------


async def test_triage_import_of_the_real_doc(ctx, db, triage_text):
    await _team(ctx, db)
    rows = triage.parse_triage(triage_text)
    stats = await triage.import_rows(ctx, db, rows, email_bodies={"E1": "e1", "E2": "e2", "E3": "e3"})
    await db.commit()
    assert stats["created"] == 90 and stats["notes"] >= 70
    tickets = {t.source_ref: t for t in (await db.execute(select(Ticket))).scalars().all()}
    assert len(tickets) == 90
    assert tickets["15"].status == "patched" and tickets["15"].internal_ref == "#1028"
    assert tickets["70"].status == "fixing"
    assert (
        tickets["89"].status == "closed"
        and tickets["89"].duplicate_of == tickets["15"].id
        and tickets["89"].internal_ref == "#1028"
    )
    assert tickets["E1"].visibility == "private" and tickets["E1"].duplicate_of == tickets["14"].id
    assert tickets["E1"].body == "" and tsvc.body_for(ctx, tickets["E1"]) == "e1"
    assert tickets["61"].duplicate_of == tickets["E1"].id
    assert (
        tickets["99"].kind == "support"
        and tickets["99"].status == "closed"
        and tickets["99"].internal_ref == "faucet#10"
        and tickets["99"].area == "testnet-faucet"  # a support row takes a topic, not a bounty area
    )
    assert tickets["57"].area == "ops-testnet"
    assert tickets["8"].assessed_tier == "severe" and tickets["8"].claimed_tier is None  # "mixed" bundle
    assert tickets["21"].mainnet_gate == "decide" and tickets["21"].status == "accepted"
    gates = Counter(t.mainnet_gate for t in tickets.values())
    assert gates["before"] == 35 and gates["later"] == 29 and gates["decide"] == 1  # as the rows say
    prs = {(p.repo, p.ref) for p in await thread.patches_for(db, tickets["15"])}
    assert prs == {("xeprotocol/xe", "27"), ("xeprotocol/xe", "111"), ("xeprotocol/xe", "1029")}
    notes = (await db.execute(select(Note).where(Note.ticket_id == tickets["96"].id))).scalars().all()
    assert len(notes) == 1 and "First reading" in notes[0].body and notes[0].author.startswith("token:")
    tok = (await db.execute(select(AgentToken))).scalars().one()
    assert tok.revoked_at is not None and tok.scopes == []
    # the outbox holds what was fixed and never told
    outbox = await tsvc.outbox(db, ctx.config, authz.SYSTEM)
    assert tickets["15"].id in {t.id for t in outbox}
    # re-running changes nothing
    again = await triage.import_rows(ctx, db, rows, email_bodies={})
    await db.commit()
    assert again["created"] == 0 and again["updated"] == 0 and again["notes"] == 0 and again["patches"] == 0
    assert (await EventLog.verify(db))["ok"]
    md = await triage.export_markdown(ctx, db, authz.SYSTEM)
    assert "XE-" in md and "`#1028`" in md and md.count("\n| ") >= 90
    public_md = await triage.export_markdown(ctx, db, authz.ANON)
    assert tickets["E1"].title in md and tickets["E1"].title not in public_md
    assert public_md.count("\n| ") == md.count("\n| ") - 3
    pending = (await db.execute(select(Proposal))).scalars().all()
    assert pending == [], "the import writes facts, not proposals"


# ---- reporters -------------------------------------------------------------------------------------


class _Upload:
    """Just enough of starlette's UploadFile for the service."""

    def __init__(self, name: str, data: bytes, content_type: str = "text/plain"):
        self.filename, self._data, self.content_type = name, data, content_type

    async def read(self, n: int = -1) -> bytes:
        d, self._data = self._data[:n] if n >= 0 else self._data, b""
        return d


def _signed(kp: KeyPair, domain: bytes, payload: dict) -> SignedRequest:
    ts = time.time_ns()
    sig = kp.sign_hex(signing_target(domain, payload, ts))
    return SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig)


async def test_reporter_files_private_report_with_sealed_attachment(ctx, db, tmp_path):
    ctx.settings.blob_dir = tmp_path
    r = await rsvc.from_email(ctx, db, "alice@example.org", link_to=None)
    me = authz.Principal(kind="reporter", reporter_id=r.id)
    f = rsvc.Filing(
        kind="bounty",
        title="Escrow release double-counts",
        body="Steps: open an escrow, release twice within one block. Expected: one release. Got: two.",
        area="consensus",
        claimed_tier="high",
        private=True,
        files=[_Upload("poc.txt", b"the exploit bytes " * 10)],
    )
    t = await rsvc.file_ticket(ctx, db, r, f)
    await db.commit()
    assert t.visibility == "private" and t.reporter_id == r.id and t.claimed_tier == "high"
    assert tsvc.body_for(ctx, t).startswith("Steps")
    atts = await rsvc.attachments_for(db, t)
    assert len(atts) == 1 and atts[0].sealed
    on_disk = (tmp_path / atts[0].blob_path).read_bytes()
    assert b"exploit" not in on_disk
    a, data = await rsvc.open_attachment(ctx, db, me, t, 1)
    assert data.startswith(b"the exploit") and a.sha256 == hashlib.sha256(data).hexdigest()
    # the reporter sees their own private ticket; anonymous and another reporter do not
    assert (await tsvc.get_for(db, me, t.id)).id == t.id
    other = authz.Principal(kind="reporter", reporter_id=r.id + 1)
    for p in (authz.ANON, other):
        with pytest.raises(HTTPException) as e:
            await tsvc.get_for(db, p, t.id)
        assert e.value.status_code == 404
    assert not rsvc.owns(None, t)


async def test_critical_claim_forces_private(ctx, db):
    r = await rsvc.from_email(ctx, db, "bob@example.org", link_to=None)
    f = rsvc.Filing(
        kind="bounty",
        title="Unauthorized mint via vault",
        body="A long enough description of how the mint can be triggered without authorisation here.",
        claimed_tier="critical",
        private=False,
    )
    t = await rsvc.file_ticket(ctx, db, r, f)
    assert t.visibility == "private"


async def test_a_reporter_past_the_daily_cap_is_queued_not_refused(ctx, db):
    cap = ctx.config.daily_cap
    assert cap >= 2
    r = await rsvc.from_email(ctx, db, "flood@example.org", link_to=None)
    other = await rsvc.from_email(ctx, db, "once@example.org", link_to=None)
    team = await _team(ctx, db)
    body = "What I did, what happened, what I expected; enough words to pass the body check."
    filed = []
    for i in range(cap + 2):
        f = rsvc.Filing(kind="bounty", title=f"probe number {i} abcdef", body=body, claimed_tier="medium")
        filed.append(await rsvc.file_ticket(ctx, db, r, f))
    assert [t.queued for t in filed] == [False] * cap + [True, True], "the first `cap` are read first"
    # support questions are not capped, and one account's flood does not touch another's first report
    ask = rsvc.Filing(kind="support", title="how do I run a node", body=body)
    q = await rsvc.file_ticket(ctx, db, r, ask)
    first = rsvc.Filing(kind="bounty", title="a real finding", body=body)
    one = await rsvc.file_ticket(ctx, db, other, first)
    assert not q.queued and not one.queued
    # queued reports sort after everything else, in both orders, and can be filtered out
    ids = [t.id for t in await tsvc.list_tickets(db, ctx.config, team, tsvc.Filters(sort="age", limit=500))]
    tail = {filed[-2].id, filed[-1].id}
    assert set(ids[-2:]) == tail and one.id in ids[:-2]
    by_sev = [t.id for t in await tsvc.list_tickets(db, ctx.config, team, tsvc.Filters(limit=500))]
    assert set(by_sev[-2:]) == tail
    unqueued = await tsvc.list_tickets(db, ctx.config, team, tsvc.Filters(queued=False, limit=500))
    assert filed[-1].id not in {t.id for t in unqueued} and one.id in {t.id for t in unqueued}
    # the record a reviewer sees beside the name
    rec = (await rsvc.records(db, {r.id, other.id}))
    assert rec[r.id]["filed"] == cap + 2 and rec[r.id]["queued"] == 2 and rec[r.id]["today"] == cap + 2
    assert rec[other.id] == {
        "filed": 1, "real": 0, "duplicate": 0, "noise": 0, "awarded": 0, "unread": 1, "today": 1, "queued": 0
    }
    # a person reaching the ticket clears the mark; the reporter sees it was read in turn
    await tsvc.set_status(ctx, db, team, filed[-1], "triaging")
    assert filed[-1].queued is False
    assert tsvc.to_dict(ctx, filed[-2], team)["queued"] is True
    assert "queued" not in tsvc.to_dict(ctx, filed[-2], authz.ANON), "an account's pace is not public"
    as_r = authz.Principal(kind="reporter", reporter_id=r.id)
    assert tsvc.to_dict(ctx, filed[-2], as_r)["queued"] is True
    evs = await EventLog.page(db, 0, 50, ref=filed[-2].id, public_only=False)
    assert any(e.kind == "ticket.queued" for e in evs)
    assert not any(e.kind == "ticket.queued" for e in await EventLog.page(db, 0, 50, ref=filed[-2].id))


async def test_reporter_withdraws_and_replies(ctx, db):
    r = await rsvc.from_email(ctx, db, "carol@example.org", link_to=None)
    team = await _team(ctx, db)
    body = "What I did, what happened, what I expected; enough words to pass the body check."
    f = rsvc.Filing(kind="bounty", title="Explorer shows wrong tip", body=body)
    t = await rsvc.file_ticket(ctx, db, r, f)
    await tsvc.set_status(ctx, db, team, t, "triaging")
    await tsvc.set_status(ctx, db, team, t, "needs-info")
    m = await rsvc.reply(ctx, db, r, t, "Here is the version: 0.5.1")
    assert m is not None and t.status == "triaging"
    await rsvc.withdraw(ctx, db, r, t, "my mistake")
    assert t.status == "closed" and t.closed_reason == "withdrawn"
    with pytest.raises(HTTPException) as e:
        await rsvc.withdraw(ctx, db, r, t)
    assert e.value.status_code == 409
    stranger = await rsvc.from_email(ctx, db, "dave@example.org", link_to=None)
    with pytest.raises(HTTPException) as e:
        await rsvc.reply(ctx, db, stranger, t, "mine now")
    assert e.value.status_code == 403


async def test_support_questions_take_topics_not_areas(ctx, db):
    r = await rsvc.from_email(ctx, db, "gail@example.org", link_to=None)
    body = "I wrote the seed down when I made the wallet but the paper is gone. Is there any way back in?"
    f = rsvc.Filing(kind="support", title="I have lost my key", body=body, area="wallet-keys")
    t = await rsvc.file_ticket(ctx, db, r, f)
    assert t.kind == "support" and t.area == "wallet-keys" and t.visibility == "public"
    # a bounty area is not a topic; it is dropped on filing and refused on edit
    f2 = rsvc.Filing(kind="support", title="When does the token launch", body=body, area="consensus")
    assert (await rsvc.file_ticket(ctx, db, r, f2)).area is None
    team = await _team(ctx, db)
    with pytest.raises(HTTPException):
        await tsvc.set_facts(ctx, db, team, t, {"area": "consensus"})
    await tsvc.set_facts(ctx, db, team, t, {"area": "safety"})
    assert t.area == "safety"
    # the support outbox is its own list: a question closed as answered with no answer written
    await tsvc.set_status(ctx, db, team, t, "triaging")
    await tsvc.set_status(ctx, db, team, t, "closed", closed_reason="answered")
    assert [x.id for x in await tsvc.outbox(db, ctx.config, team, kind="support")] == [t.id]
    assert await tsvc.outbox(db, ctx.config, team) == []  # the bounty outbox never shows a question
    await thread.add_reply(ctx, db, team, t, "A seed cannot be recovered by anyone; a new wallet is the way.")
    assert await tsvc.outbox(db, ctx.config, team, kind="support") == []


async def test_payout_binding_needs_matching_key(ctx, db):
    r = await rsvc.from_email(ctx, db, "erin@example.org", link_to=None)
    body = "A public report with enough body to be accepted by the filing checks, no secrets inside."
    f = rsvc.Filing(kind="bounty", title="Typo on the faucet page", body=body)
    t = await rsvc.file_ticket(ctx, db, r, f)
    kp, wrong = KeyPair.generate(), KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_PAYOUT, {"address": wrong.address}), DOMAIN_PAYOUT)
    with pytest.raises(HTTPException) as e:
        await rsvc.bind_payout(ctx, db, r, v)
    assert e.value.status_code == 400
    v = await verify_signed(db, _signed(kp, DOMAIN_PAYOUT, {"address": kp.address}), DOMAIN_PAYOUT)
    out = await rsvc.bind_payout(ctx, db, r, v)
    assert out == {"address": kp.address, "tickets_updated": 1}
    assert r.xe_address == kp.address and t.payout_address == kp.address
    # an address is 64 hex like a seed; pasted as one it yields a key anyone can derive (XS-0008)
    trap = KeyPair.from_seed_hex(kp.address)
    v = await verify_signed(db, _signed(trap, DOMAIN_PAYOUT, {"address": trap.address}), DOMAIN_PAYOUT)
    with pytest.raises(HTTPException) as e:
        await rsvc.bind_payout(ctx, db, r, v)
    assert e.value.status_code == 400 and "public address" in e.value.detail
    assert r.xe_address == kp.address
    # the reporter can take the address off again; unpaid tickets lose it, and twice is a 409
    assert await rsvc.unbind_payout(ctx, db, r) == {"tickets_updated": 1}
    assert r.xe_address == "" and t.payout_address == "" and r.payout_proof == {}
    with pytest.raises(HTTPException) as e:
        await rsvc.unbind_payout(ctx, db, r)
    assert e.value.status_code == 409
    v = await verify_signed(db, _signed(kp, DOMAIN_PAYOUT, {"address": kp.address}), DOMAIN_PAYOUT)
    await rsvc.bind_payout(ctx, db, r, v)
    # the payout export lists tickets at awarded with the bound address, and nothing before that
    team = await _team(ctx, db)
    await tsvc.set_status(ctx, db, team, t, "triaging")
    t.assessed_tier, t.award_xe, t.award_approved_at = "minor", 5_000_000, utcnow()
    await db.flush()
    assert await rsvc.payout_rows(db) == []  # approved while triaging is not payable (XE-0300)
    for st in ("accepted", "patched", "awarded"):
        await tsvc.set_status(ctx, db, team, t, st)
    rows = await rsvc.payout_rows(db)
    assert rows and rows[0]["ticket"] == t.id and rows[0]["status"] == "awarded"
    assert rows[0]["award_xe"] == 5_000_000 and rows[0]["xe_address"] == kp.address
    assert rows[0]["stamped_address"] == kp.address and not rows[0]["address_changed"]
    # a rebind after the award refreshes the stamp: one address in both treasurer views (XE-0711)
    kp2 = KeyPair.generate()
    v = await verify_signed(db, _signed(kp2, DOMAIN_PAYOUT, {"address": kp2.address}), DOMAIN_PAYOUT)
    assert (await rsvc.bind_payout(ctx, db, r, v))["tickets_updated"] == 1
    rows = await rsvc.payout_rows(db)
    assert rows[0]["xe_address"] == kp2.address == rows[0]["stamped_address"] == t.payout_address
    # reporter-written cells never start a formula in the treasurer's spreadsheet (XE-0714)
    assert rsvc.csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and rsvc.csv_cell("plain") == "plain"
    assert rsvc.csv_cell("-1") == "'-1" and rsvc.csv_cell(5) == "5" and rsvc.csv_cell(None) == ""


async def test_xe_login_and_identity_merge(ctx, db):
    kp = KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    a = await rsvc.from_xe(ctx, db, v, link_to=None)
    assert kp.address in a.xe_login_addresses
    # an email account exists separately, with a ticket. Mail never merges: whoever clicks a link proved
    # the mailbox, not the other account (XE-0199)
    b = await rsvc.from_email(ctx, db, "frank@example.org", link_to=None)
    body = "Filed under the email identity before the two accounts were joined together by the reporter."
    f = rsvc.Filing(kind="support", title="Which port does a node use", body=body)
    t = await rsvc.file_ticket(ctx, db, b, f)
    with pytest.raises(HTTPException) as e:
        await rsvc.from_email(ctx, db, "frank@example.org", link_to=a)
    assert e.value.status_code == 409
    # a key signed in the email account's own session does merge: the signer holds both
    v2 = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    merged = await rsvc.from_xe(ctx, db, v2, link_to=b)
    assert merged.id == b.id and kp.address in merged.xe_login_addresses
    await db.refresh(t)
    assert t.reporter_id == b.id
    assert (await rsvc.get(db, a.id)).xe_login_addresses == []  # emptied, kept so old log entries resolve
    a = b
    # link tokens: one use, then gone
    raw = await auth.create_reporter_link(db, "frank@example.org", a.id, "/my")
    link = await auth.consume_reporter_link(db, raw)
    assert link is not None and link.reporter_id == a.id and link.next_path == "/my"
    assert await auth.consume_reporter_link(db, raw) is None


async def test_a_recycled_github_login_cannot_claim_a_bound_row(ctx, db):
    victim = await rsvc.from_github(ctx, db, {"id": 1111, "login": "ghost", "name": "G"}, "", link_to=None)
    # the login lookup only claims rows no GitHub identity has signed in to (XE-0228)
    assert await rsvc.by_github(db, 9999, "ghost") is None
    other = await rsvc.from_github(ctx, db, {"id": 9999, "login": "ghost", "name": "X"}, "", link_to=None)
    assert other.id != victim.id and victim.github_id == 1111
    # and a row with one GitHub identity never takes a second
    with pytest.raises(HTTPException) as e:
        await rsvc.from_github(ctx, db, {"id": 4242, "login": "ghost2"}, "", link_to=victim)
    assert e.value.status_code == 409
    # an imported row (login only) is still claimed on first sign-in
    imported = await sync.reporter_for(db, {"id": None, "login": "newcomer"})
    assert imported.github_id is None
    claimed = await rsvc.from_github(ctx, db, {"id": 5, "login": "newcomer"}, "", link_to=None)
    assert claimed.id == imported.id and claimed.github_id == 5


async def test_disclosing_by_any_route_unseals_and_publishes(ctx, db):
    team = await _team(ctx, db)
    spec = tsvc.NewTicket(
        kind="bounty", title="sealed", body="the exploit", visibility="private", source="web"
    )
    t = await tsvc.create(ctx, db, team.actor, spec)
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, team, t, st)
    await thread.add_patch_ref(ctx, db, team, t, repo="xeprotocol/xe", ref="9", kind="pr")
    # the leaderboard never shows a private award (XE-0310)
    t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
    await tsvc.set_award(ctx, db, team, t, 5_000_000, approve=True)
    await tsvc.set_status(ctx, db, team, t, "awarded", force=True)
    assert await tsvc.leaderboard(db) == []
    await tsvc.set_status(ctx, db, team, t, "patched", force=True)
    # a walked path (what a proposal adopts) reaches disclosed through set_status, which is the one
    # disclosure path: visibility flips, the body leaves the vault, the public event is written (XE-0210)
    path = await tsvc.set_status_via_path(ctx, db, team, t, "disclosed", via="proposal:1")
    assert path == ["disclosed"]
    assert t.visibility == "public" and t.body == "the exploit" and t.body_sealed is None
    kinds = [e.kind for e in await EventLog.page(db, 0, 20, ref=t.id, public_only=True)]
    assert "ticket.disclosed" in kinds
    # javascript: never reaches an href (XE-0234 A)
    with pytest.raises(HTTPException):
        await thread.add_patch_ref(
            ctx, db, team, t, repo="xeprotocol/xe", ref="10", kind="pr", url="javascript:1"
        )


async def test_payout_file_lists_only_awarded_tickets(ctx, db):
    team = await _team(ctx, db)
    async def mk(n):
        return await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title=n, source="web"))

    live, closed, paid = await mk("live"), await mk("closed"), await mk("paid")
    for t in (live, closed, paid):
        for st in ("triaging", "accepted", "patched"):
            await tsvc.set_status(ctx, db, team, t, st)
        t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
        await tsvc.set_award(ctx, db, team, t, 1_000_000, approve=True)
        await tsvc.set_status(ctx, db, team, t, "awarded")
    await tsvc.set_status(ctx, db, team, closed, "closed", closed_reason="invalid", force=True)
    paid.paid_ref = "tx"
    await tsvc.set_status(ctx, db, team, paid, "paid")
    rows = await rsvc.payout_rows(db)
    assert [r["ticket"] for r in rows] == [live.id] and rows[0]["status"] == "awarded"
    # paid is recorded through mark_paid, treasurer only, awarded only; the record does not walk back
    live.assessed_tier = "minor"
    with pytest.raises(HTTPException) as e:
        await tsvc.mark_paid(ctx, db, team, closed, "tx2")
    assert e.value.status_code == 409
    await tsvc.mark_paid(ctx, db, team, live, " tx-abc ")
    assert live.status == "paid" and live.paid_ref == "tx-abc" and await rsvc.payout_rows(db) == []
    with pytest.raises(HTTPException) as e:
        await tsvc.set_status(ctx, db, team, live, "awarded")  # XE-0789
    assert e.value.status_code == 409


async def test_tokens_stop_when_the_owner_leaves_the_team(ctx, db):
    lead = await _team(ctx, db)
    agent = await _agent(ctx, db, lead.user, scopes=("read:public", "read:private", "write:notes"))
    assert agent.token.revoked_at is None
    await users.set_roles(ctx, db, "test", lead.user, [])
    assert agent.token.revoked_at is not None


async def test_making_a_ticket_private_seals_what_arrived_while_public(ctx, db, tmp_path):
    ctx.settings.blob_dir = str(tmp_path)
    team = await _team(ctx, db)
    t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(77, "public then private", body="b"))
    # a stranger quoting the marker is not the team (XE-0200); the bot login is
    ctx.settings.github_bot_login = "xe-desk-bot"
    mallory = {"id": 1, "user": {"login": "mallory"}, "body": "hi <!-- xe-desk -->"}
    bot = {"id": 2, "user": {"login": "xe-desk-bot"}, "body": "we read it"}
    await sync.upsert_comment(ctx, db, t, mallory)
    await sync.upsert_comment(ctx, db, t, bot)
    msgs = await thread.messages_for(db, t)
    assert [(m.author, m.author_is_team) for m in msgs] == [("mallory", False), ("xe-desk-bot", True)]
    assert msgs[0].body == "hi"
    r = await thread.add_reply(ctx, db, team, t, "queued for github")
    assert r.mirror == "queued"
    await tsvc.set_facts(ctx, db, team, t, {"visibility": "private"})
    msgs = await thread.messages_for(db, t)
    assert all(m.body == "" and m.body_sealed for m in msgs)
    assert thread.message_body(ctx, t, msgs[0]) == "hi"
    await db.refresh(r)
    assert r.mirror == "none"
    assert await sync.queued_replies(db) == [] or r not in await sync.queued_replies(db)


# ---- chat channels (the bot's database side) --------------------------------------------------------------


def _post(uid="1001", **kw) -> channels.ChannelPost:
    base = dict(
        platform="discord",
        thread_ref="555",
        thread_url="https://discord.com/channels/1/2/555",
        user_id=uid,
        user_name="Ada",
        user_handle="ada",
        title="When does the token launch",
        body="Saw a date in a Telegram group; is it real?",
        topic="launch-token",
    )
    base.update(kw)
    return channels.ChannelPost(**base)


async def test_discord_thread_becomes_a_support_ticket(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    await db.commit()
    assert t.kind == "support" and t.source == "discord" and t.source_ref == "555"
    assert t.area == "launch-token" and t.channel_state == "open" and t.visibility == "public"
    r = await channels.by_platform(db, "discord", "1001")
    assert r is not None and r.id == t.reporter_id and r.platform_ids["discord_handle"] == "ada"
    assert (await channels.ticket_for(db, "discord", "555")).id == t.id
    # the same person asking again is the same reporter
    t2 = await channels.open_from_channel(ctx, db, _post(thread_ref="556", title="And where is the wallet"))
    assert t2.reporter_id == r.id
    # the bot's lines come from the public register with the ticket filled in
    created = channels.bot_text(ctx, "created", t)
    assert t.id in created and "support.test" in created


async def test_discord_messages_thread_and_move_status(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    team = await _team(ctx, db)
    # the team's first word in the thread starts triage
    m = await channels.incoming(
        ctx, db, t, message_ref="m1", user_id="9", user_name="Bea", body="Looking.", is_team=True
    )
    assert m is not None and m.author_is_team and t.status == "triaging"
    # idempotent on the platform message id
    tk = dict(user_id="9", user_name="Bea", is_team=True)
    again = await channels.incoming(ctx, db, t, message_ref="m1", body="x", **tk)
    assert again is None
    # needs-info, then the reporter answers: back to triage; a stranger's message does not
    await tsvc.set_status(ctx, db, team, t, "needs-info")
    kw = dict(user_name="x", is_team=False)
    await channels.incoming(ctx, db, t, message_ref="m2", user_id="2002", body="me", **kw)
    assert t.status == "needs-info"
    await channels.incoming(ctx, db, t, message_ref="m3", user_id="1001", body="hi", **kw)
    assert t.status == "triaging"
    msgs = await thread.messages_for(db, t)
    assert [x.source_ref for x in msgs] == ["m1", "m2", "m3"]
    # attachments become lines, an empty message is nothing
    await channels.incoming(
        ctx, db, t, message_ref="m4", user_id="1001", user_name="Ada", body="", is_team=False,
        attachments=["https://cdn/x.png"],
    )
    last = (await thread.messages_for(db, t))[-1]
    assert "Attachment: https://cdn/x.png" in thread.message_body(ctx, t, last)
    blank = await channels.incoming(ctx, db, t, message_ref="m5", user_id="1001", body="  ", **kw)
    assert blank is None


async def test_desk_reply_is_queued_for_the_bot_not_the_worker(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    team = await _team(ctx, db)
    r = await thread.add_reply(ctx, db, team, t, "There is no announced date.")
    assert r.mirror == "queued"
    assert await sync.queued_replies(db) == []  # the worker leaves it alone
    pairs = await channels.queued_replies(db, "discord")
    assert [(x.id, y.id) for x, y in pairs] == [(r.id, t.id)]
    text = channels.reply_text(ctx, t, r)
    assert "XE team" in text and t.id in text
    await channels.mark_mirrored(ctx, db, r, t, message_ref="d9", url="https://discord.com/x")
    assert r.mirror == "sent" and r.mirror_ref == "https://discord.com/x"
    assert [x.source_ref for x in await thread.messages_for(db, t)][-1] == "d9"
    assert await channels.queued_replies(db, "discord") == []


async def test_reporter_with_an_email_is_told_of_team_replies(ctx, db, monkeypatch):
    sent: list[tuple[str, str, str]] = []

    async def fake_mail(settings, to, subject, body):
        sent.append((to, subject, body))
        return True

    monkeypatch.setattr(auth, "send_mail", fake_mail)
    ctx.settings.smtp_host = "mail.test"
    team = await _team(ctx, db)
    words = "What I did, what happened, and what I expected instead, in enough words to pass the check."

    def filing(title, private):
        return rsvc.Filing(kind="bounty", title=title, body=words, private=private)

    # a key-only reporter: nobody to tell
    kp = KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    silent = await rsvc.from_xe(ctx, db, v, link_to=None)
    t1 = await rsvc.file_ticket(ctx, db, silent, filing("Quiet report", True))
    assert await notify.reply_to_reporter(ctx, db, t1, team.name, "Looking.") is False
    # an email on the account: a private report gets the fact and the link, not the text
    r = await rsvc.from_email(ctx, db, "alice@example.org", link_to=None)
    t2 = await rsvc.file_ticket(ctx, db, r, filing("Private report", True))
    assert await notify.reply_to_reporter(ctx, db, t2, team.name, "Confirmed, fixing.") is True
    to, subject, body = sent[-1]
    assert to == "alice@example.org" and t2.id in subject and "Confirmed" not in body and t2.id in body
    # a public one carries the text
    t3 = await rsvc.file_ticket(ctx, db, r, filing("Public typo", False))
    assert await notify.reply_to_reporter(ctx, db, t3, team.name, "Fixed in #27.") is True
    assert "Fixed in #27." in sent[-1][2]
    # a Discord-sourced question is told in its thread by the bot, not by mail
    t4 = await channels.open_from_channel(ctx, db, _post())
    assert await notify.reply_to_reporter(ctx, db, t4, team.name, "No date yet.") is False
    # mail off: nothing goes out, nothing breaks
    ctx.settings.smtp_host = ""
    assert await notify.reply_to_reporter(ctx, db, t3, team.name, "Again.") is False


async def test_close_convert_rename_from_the_channel_and_state_push(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    assert await channels.needing_state_push(db, "discord") == []
    assert await channels.close_from_channel(ctx, db, t, user_id="9", reason="stale, no reply") == "stale"
    assert t.status == "closed" and t.closed_reason == "stale" and t.channel_state == "closed"
    assert "Stale" in channels.closed_line(ctx, t) or "stale" in channels.closed_line(ctx, t)
    # closed on the desk instead: the bot finds it and marks the thread
    t2 = await channels.open_from_channel(ctx, db, _post(thread_ref="777", title="Lost my key, any way back"))
    team = await _team(ctx, db)
    await tsvc.set_status(ctx, db, team, t2, "triaging")
    await tsvc.set_status(ctx, db, team, t2, "closed", closed_reason="answered")
    assert [x.id for x in await channels.needing_state_push(db, "discord")] == [t2.id]
    await channels.mark_state(ctx, db, t2, "closed")
    assert await channels.needing_state_push(db, "discord") == []
    await channels.reopen_from_channel(ctx, db, t2, user_id="9")
    assert t2.status == "triaging" and t2.channel_state == "open"
    # a question that is a bug
    new = await channels.rename_from_channel(ctx, db, t2, user_id="9", title="Escrow releases twice")
    assert t2.title == new
    await channels.convert_to_bounty(ctx, db, t2, user_id="9")
    assert t2.kind == "bounty" and t2.area is None
    with pytest.raises(HTTPException):
        await channels.convert_to_bounty(ctx, db, t2, user_id="9")
    assert "proof of concept" in channels.bot_text(ctx, "converted", t2)


async def test_discord_identity_links_to_a_web_account(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    shell = await channels.by_platform(db, "discord", "1001")
    web = await rsvc.from_email(ctx, db, "ada@example.org", link_to=None)
    merged = await channels.from_platform(ctx, db, "discord", "1001", name="Ada", link_to=web)
    assert merged.id == web.id and merged.platform_ids["discord"] == "1001"
    await db.refresh(t)
    assert t.reporter_id == web.id
    assert [x.id for x in await rsvc.my_tickets(db, web)] == [t.id]
    # the merged-away row keeps no platform id, so the next Discord message keys to the live account
    # (XE-0473), and no session or link of the shell survives the merge (XE-0710)
    await db.refresh(shell)
    assert shell.platform_ids == {} and (await channels.by_platform(db, "discord", "1001")).id == web.id
    t2 = await channels.open_from_channel(ctx, db, _post(thread_ref="556"))
    assert t2.reporter_id == web.id


async def test_identities_come_off_an_account_and_other_sessions_end(ctx, db):
    kp = KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    r = await rsvc.from_xe(ctx, db, v, link_to=None)
    with pytest.raises(HTTPException) as e:
        await rsvc.unlink(ctx, db, r, "xe", kp.address)  # the only way in stays
    assert e.value.status_code == 409
    r = await rsvc.from_email(ctx, db, "pat@example.org", link_to=r)
    assert rsvc.ways_in(r) == 2
    assert (await rsvc.unlink(ctx, db, r, "xe", kp.address))["ways_in"] == 1
    assert r.xe_login_addresses == [] and await rsvc.by_login_address(db, kp.address) is None
    with pytest.raises(HTTPException):
        await rsvc.unlink(ctx, db, r, "xe", kp.address)
    # sessions: this one stays, the others go, and so do outstanding links
    s1, _ = await auth.create_reporter_session(db, r, "email")
    s2, _ = await auth.create_reporter_session(db, r, "email")
    await auth.create_reporter_link(db, "pat@example.org", r.id, "/my")
    assert await rsvc.end_other_sessions(db, r, keep=s1.id) == 1
    from desk.models import ReporterLink, ReporterSession

    left = (await db.execute(select(ReporterSession.id).where(ReporterSession.reporter_id == r.id))).scalars()
    assert list(left) == [s1.id] and s2.id != s1.id
    links = (await db.execute(select(ReporterLink).where(ReporterLink.reporter_id == r.id))).scalars().all()
    assert links == []


async def test_one_time_links_are_claimed_once_and_burn_their_siblings(ctx, db):
    # a reporter link: the first consumer wins, the second gets nothing, and the other outstanding links
    # for the address die with it (XE-0709, XE-0782)
    a = await auth.create_reporter_link(db, "sam@example.org", None, "/my")
    b = await auth.create_reporter_link(db, "sam@example.org", None, "/my")
    assert (await auth.consume_reporter_link(db, a)) is not None
    assert await auth.consume_reporter_link(db, a) is None
    assert await auth.consume_reporter_link(db, b) is None
    # signed out, a link for a known address is a plain sign-in, not one bound to the account (XE-0363)
    r = await rsvc.from_email(ctx, db, "sam@example.org", link_to=None)
    c = await auth.create_reporter_link(db, "sam@example.org", None, "/my")
    link = await auth.consume_reporter_link(db, c)
    assert link.reporter_id is None
    assert (await rsvc.from_email(ctx, db, link.email, link_to=None)).id == r.id
    # team invites: the same rule (XE-0837)
    team = await _team(ctx, db)
    i1 = await auth.create_invite(db, team.user)
    i2 = await auth.create_invite(db, team.user, purpose="magic-link")
    assert (await auth.consume_invite(db, i1)) is not None
    assert await auth.consume_invite(db, i1) is None and await auth.consume_invite(db, i2) is None
    # a deactivated member's sessions are gone, not merely refused (XE-0838)
    s, _ = await auth.create_session(db, team.user)
    await users.set_active(ctx, db, "test", team.user, False)
    from desk.models import Session

    assert (await db.execute(select(Session).where(Session.user_id == team.user.id))).scalars().all() == []
    # lookups with a NUL or a lone surrogate match nothing and raise nothing (XE-0827)
    assert await users.by_email(db, "lead@xe\x00.network") is None
    assert await rsvc.by_email(db, "a\udc80@example.org") is None
    assert auth.safe_next(ctx.settings, "/my\\evil") == "/my" and auth.safe_next(ctx.settings, "/my") == "/my"
    assert auth.safe_next(ctx.settings, "/\\evil.com") == "/my"  # XE-1092


async def test_first_sign_ins_converge_on_one_row_and_names_fit(ctx, db):
    # a provider-verified email lands on the row that already holds it (XE-1012)
    r = await rsvc.from_email(ctx, db, "kim@example.org", link_to=None)
    gh_user = {"id": 77, "login": "kim", "name": "K" * 300}
    g = await rsvc.from_github(ctx, db, gh_user, "KIM@example.org", link_to=None)
    assert g.id == r.id and g.github_id == 77 and len(g.display_name) <= 128
    d = await channels.from_platform(ctx, db, "discord", "9001", name="Kim", email="kim@example.org")
    assert d.id == r.id and d.platform_ids["discord"] == "9001"
    # a long GitHub name or local part is cut, not a 500 (XE-1085)
    long_local = "l" * 200 + "@example.org"
    e = await rsvc.from_email(ctx, db, long_local, link_to=None)
    assert len(e.display_name) == 128
    h = await rsvc.from_github(ctx, db, {"id": 78, "login": "x", "name": "N" * 200}, "", link_to=None)
    assert len(h.display_name) == 128

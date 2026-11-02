"""Against a real Postgres: the log chain, the ticket flow, proposals, the outbox, and the triage import
of the actual doc. Skipped unless DESK_TEST_DATABASE_URL is set, e.g.
DESK_TEST_DATABASE_URL=postgresql+asyncpg://desk:pw@db:5432/desk_test (a scratch database; it is wiped).

The image carries neither pytest nor this directory; mount the tests and install pytest for the run.
Run on the VPS (see docs/DEPLOY.md):

  docker compose exec db psql -U desk -d desk -c "CREATE DATABASE desk_test"   # "already exists" is fine
  docker compose run --rm --no-deps -v $PWD/tests:/app/tests \
    -e DESK_TEST_DATABASE_URL=postgresql+asyncpg://desk:$(grep ^POSTGRES_PASSWORD .env | cut -d= -f2)@db:5432/desk_test \
    app sh -c "pip install -q pytest pytest-asyncio && pytest -q tests/test_db.py"
"""

import hashlib
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
from desk.models import AgentToken, Note, Proposal, Reply, Ticket, User
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
    await db.execute(text("UPDATE events SET payload = '{\"i\": 9}'::jsonb WHERE index = 2"))
    await db.commit()
    assert "hash mismatch at 2" in (await EventLog.verify(db))["first_error"]


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
    await tsvc.set_status(ctx, db, p, t, "patched")
    assert t.status_changed_at is not None
    # outbox: patched and never told
    assert [x.id for x in await tsvc.outbox(db, ctx.config, p)] == ["XE-0001"]
    r = await thread.add_reply(ctx, db, p, t, "Fixed in #27, thank you.")
    assert r.mirror == "none" and t.told_at is not None
    assert await tsvc.outbox(db, ctx.config, p) == []
    # award needs the treasurer and approval before awarded
    with pytest.raises(HTTPException):
        await tsvc.set_status(ctx, db, p, t, "awarded")
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
        and kinds["ticket.facts"] == 1
        and kinds["reply.sent"] == 1
        and kinds["ticket.award"] == 1
    )


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


# ---- proposals --------------------------------------------------------------------------------------


async def test_agent_proposes_human_adopts(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    with pytest.raises(HTTPException):
        await psvc.propose(ctx, db, p, t, "verdict", "valid", "people set facts directly")
    pr1 = await psvc.propose(ctx, db, agent, t, "verdict", "valid", "reproduced")
    pr2 = await psvc.propose(ctx, db, agent, t, "assessed_tier", "high", "targeted DoS")
    pr3 = await psvc.propose(ctx, db, agent, t, "reply_draft", "Thanks, reproduced.", "")
    out = await psvc.decide(ctx, db, p, pr1, True)
    assert out["diff"]["verdict"]["to"] == "valid" and t.verdict == "valid"
    with pytest.raises(HTTPException) as e:
        await psvc.decide(ctx, db, p, pr2, True)  # reviewer lacks the tier role
    assert e.value.status_code == 403 and pr2.state == "pending"
    out = await psvc.decide(ctx, db, p, pr3, True)
    assert out["reply_draft"] == "Thanks, reproduced." and t.status == "new"
    assert (await db.execute(select(Reply))).scalars().all() == []
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
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=True)
    assert t.id not in [d.id for d in await tsvc.awards_due(db, ctx.config, treasurer)]
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
    # the payout export lists approved awards with the bound address
    await tsvc.set_status(ctx, db, await _team(ctx, db), t, "triaging")
    t.award_xe, t.award_approved_at = 5_000_000, utcnow()
    await db.flush()
    rows = await rsvc.payout_rows(db)
    assert rows and rows[0][0] == t.id and rows[0][3] == 5 and rows[0][-1] == kp.address


async def test_xe_login_and_identity_merge(ctx, db):
    kp = KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    a = await rsvc.from_xe(ctx, db, v, link_to=None)
    assert kp.address in a.xe_login_addresses
    # an email account exists separately, with a ticket; linking email onto the key account merges them
    b = await rsvc.from_email(ctx, db, "frank@example.org", link_to=None)
    body = "Filed under the email identity before the two accounts were joined together by the reporter."
    f = rsvc.Filing(kind="support", title="Which port does a node use", body=body)
    t = await rsvc.file_ticket(ctx, db, b, f)
    merged = await rsvc.from_email(ctx, db, "frank@example.org", link_to=a)
    assert merged.id == a.id and merged.email == "frank@example.org"
    await db.refresh(t)
    assert t.reporter_id == a.id
    assert (await rsvc.get(db, b.id)).email == ""  # emptied, kept so old log entries still resolve
    # link tokens: one use, then gone
    raw = await auth.create_reporter_link(db, "frank@example.org", a.id, "/my")
    link = await auth.consume_reporter_link(db, raw)
    assert link is not None and link.reporter_id == a.id and link.next_path == "/my"
    assert await auth.consume_reporter_link(db, raw) is None


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
    web = await rsvc.from_email(ctx, db, "ada@example.org", link_to=None)
    merged = await channels.from_platform(ctx, db, "discord", "1001", name="Ada", link_to=web)
    assert merged.id == web.id and merged.platform_ids["discord"] == "1001"
    await db.refresh(t)
    assert t.reporter_id == web.id
    assert [x.id for x in await rsvc.my_tickets(db, web)] == [t.id]

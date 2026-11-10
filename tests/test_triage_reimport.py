"""Re-running the triage import never moves a ticket backwards. Same Postgres as test_db; skipped
without DESK_TEST_DATABASE_URL."""

import os

import pytest

from desk.services import tickets as tsvc
from desk.services import triage
from tests.test_db import _team, ctx, db  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not os.environ.get("DESK_TEST_DATABASE_URL"), reason="DESK_TEST_DATABASE_URL not set")


async def test_reimport_leaves_a_ticket_a_person_has_moved_on(ctx, db, triage_text):  # noqa: F811
    team = await _team(ctx, db)
    rows = triage.parse_triage(triage_text)
    first = await triage.import_rows(ctx, db, rows, email_bodies={"E1": "e1", "E2": "e2", "E3": "e3"})
    await db.commit()
    assert first["status_kept"] == 0
    found = [await triage._find(db, r) for r in rows if r.status()[0] == "accepted"]
    t = next(x for x in found if x.visibility == "public")  # an award is public (XE-2250)
    assert t.status == "accepted"
    # the team takes it to awarded after the sheet was written
    for st in ("patched", "awarded"):
        await tsvc.set_status(ctx, db, team, t, st, force=True)
    await db.commit()
    again = await triage.import_rows(ctx, db, rows, email_bodies={})
    await db.commit()
    assert t.status == "awarded" and again["status_kept"] == 1 and again["updated"] == 0
    # a ticket nobody has taken past triage still follows the sheet, along the allowed path
    t.status, t.closed_reason, t.status_changed_at = "new", None, None
    await db.commit()
    await triage.import_rows(ctx, db, rows, email_bodies={})
    await db.commit()
    assert t.status == "accepted"


async def test_reimport_leaves_what_has_been_ruled_since(ctx, db):  # noqa: F811
    """The rule (XE-2051): the sheet writes over a ticket's facts only while the ticket is still in the
    statuses the import owns; past them it fills what is empty and changes nothing; an empty cell never
    erases. Asked of every fact the import writes, with rows built here (no private sheet needed)."""
    team = await _team(ctx, db)
    sheet = dict(
        area="consensus", verdict="valid", gate="before", claimed_tier="high", assessed_tier="medium",
        effort="1-4h", internal_ref="#1001",
    )
    ruled = dict(
        area="p2p-sync", verdict="likely-valid", mainnet_gate="later", claimed_tier="medium",
        assessed_tier="high", effort_eng="1-3d", internal_ref="#2002",
    )

    def row(key, **cells):
        url = f"https://github.com/xeprotocol/xe/issues/{key}"
        return triage.Row(key=key, repo="xeprotocol/xe", url=url, title=f"Sheet row {key}", **cells)

    def facts(t):
        return {k: getattr(t, k) for k in ruled}

    # first import: the sheet starts the ticket off, facts and status
    first = await triage.import_rows(ctx, db, [row("901", **sheet)])
    t = await triage._find(db, row("901"))
    assert first["created"] == 1 and first["updated"] == 1 and t.status == "accepted"
    assert (t.assessed_tier, t.verdict, t.mainnet_gate, t.effort_eng, t.internal_ref) == (
        "medium", "valid", "before", "1-4h", "#1001"
    )
    # the team rules on it; the same sheet again, and then a sheet with every cell empty, change nothing
    await tsvc.set_facts(ctx, db, team, t, ruled)
    for cells in (sheet, {}):
        again = await triage.import_rows(ctx, db, [row("901", **cells)])
        assert facts(t) == ruled, cells
        assert again["updated"] == 0 and again["facts_kept"] == (1 if cells else 0), cells
    # past triage the sheet still fills a fact nobody has set
    await tsvc.set_facts(ctx, db, team, t, {"effort_eng": None})
    again = await triage.import_rows(ctx, db, [row("901", **sheet)])
    assert again["updated"] == 1 and facts(t) == {**ruled, "effort_eng": "1-4h"}
    # an award approved under the ruled tier, then made: the import runs, the tier and the approval stand
    await tsvc.set_status(ctx, db, team, t, "patched")
    await tsvc.set_award(ctx, db, team, t, 5_000_000, approve=True)
    for st in ("patched", "awarded"):
        if t.status != st:
            await tsvc.set_status(ctx, db, team, t, st)
        again = await triage.import_rows(ctx, db, [row("901", **sheet)])
        assert (t.status, t.assessed_tier) == (st, "high") and t.award_approved_at is not None, st
        assert again["status_kept"] == 1 and again["facts_kept"] == 1 and again["updated"] == 0, st
    # a ticket nobody has taken past triage still follows the sheet, and an empty cell erases nothing
    early = dict(sheet, internal_ref="")
    await triage.import_rows(ctx, db, [row("902", **early)])
    t2 = await triage._find(db, row("902"))
    assert t2.status == "triaging" and t2.assessed_tier == "medium"
    await tsvc.set_facts(ctx, db, team, t2, {"assessed_tier": "high", "internal_ref": "#3003"})
    await triage.import_rows(ctx, db, [row("902", **early)])
    assert (t2.assessed_tier, t2.internal_ref) == ("medium", "#3003")

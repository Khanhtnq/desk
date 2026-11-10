"""Re-running the triage import never moves a ticket backwards. Same Postgres as test_db; skipped
without DESK_TEST_DATABASE_URL."""

import os
import re

import pytest
from fastapi import HTTPException

from desk.authz import SYSTEM
from desk.services import thread, triage
from desk.services import tickets as tsvc
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


async def test_reimport_leaves_the_rulings_a_status_does_not_show(ctx, db):  # noqa: F811
    """The same rule, asked of what a person or GitHub rules without taking the ticket past triage, or
    without leaving a value behind: waiting on the reporter, the move to the support door, a tracker
    link cleared by hand, a duplicate re-pointed, a patch link GitHub has reported on, and a tier
    behind an award of nothing."""
    team = await _team(ctx, db)
    xe = "xeprotocol/xe"
    sheet = dict(
        area="consensus", verdict="valid", gate="before", claimed_tier="high", assessed_tier="medium",
        effort="1-4h",
    )
    tracked = dict(sheet, internal_ref="#1001")

    def row(key, **cells):
        url = f"https://github.com/{xe}/issues/{key}"
        return triage.Row(key=key, repo=xe, url=url, title=f"Sheet row {key}", **cells)

    async def started(key, **cells):
        await triage.import_rows(ctx, db, [row(key, **cells)])
        return await triage._find(db, row(key))

    # needs-info: no row says it, so a person put the ticket there; it is not moved and not written over
    a = await started("911", **sheet)
    assert a.status == "triaging"
    await tsvc.set_status(ctx, db, team, a, "needs-info")
    await tsvc.set_facts(ctx, db, team, a, {"assessed_tier": "high"})
    again = await triage.import_rows(ctx, db, [row("911", **sheet)])
    assert (a.status, a.assessed_tier) == ("needs-info", "high")
    assert again["status_kept"] == 1 and again["facts_kept"] == 1 and again["updated"] == 0

    # the support door: the import never converts. Not back to the bounty while the question is open,
    # and a row that would close it with a reason the support door does not have stops nothing
    b = await started("912", **sheet)
    await tsvc.set_kind(ctx, db, team.actor, b, "support")
    await tsvc.set_facts(ctx, db, team, b, {"area": "getting-started"})
    for cells in (sheet, dict(sheet, verdict="invalid"), tracked):
        again = await triage.import_rows(ctx, db, [row("912", **cells)])
        assert (b.kind, b.status, b.area) == ("support", "triaging", "getting-started"), cells
        assert (b.claimed_tier, b.verdict, b.internal_ref) == (None, "valid", ""), cells
        assert again["updated"] == 0 and again["facts_kept"] == 1, cells
        assert again["status_kept"] == (0 if cells is sheet else 1), cells

    # a tracker link the ticket followed and a person then cleared is not put back, past triage or in it
    c = await started("913", **tracked)
    assert (c.status, c.internal_ref) == ("accepted", "#1001")
    c.internal_followed = "#1001:open:"  # as sync leaves it once the tracker has been read
    await tsvc.set_facts(ctx, db, team, c, {"internal_ref": ""})
    again = await triage.import_rows(ctx, db, [row("913", **tracked)])
    assert c.internal_ref == "" and again["updated"] == 0 and again["facts_kept"] == 1
    await tsvc.set_status(ctx, db, team, c, "triaging")
    await triage.import_rows(ctx, db, [row("913", **tracked)])
    assert c.internal_ref == ""

    # a duplicate takes its canonical and the canonical's tracker link from the sheet; re-pointed by a
    # person, both stand
    pair = [
        row("914", **dict(sheet, internal_ref="#1004")),
        row("915", verdict="duplicate", duplicate_of_key="914"),
    ]
    await triage.import_rows(ctx, db, pair)
    canon, d = await triage._find(db, pair[0]), await triage._find(db, pair[1])
    assert (d.status, d.closed_reason, d.duplicate_of, d.internal_ref) == (
        "closed", "duplicate", canon.id, "#1004"
    )
    await tsvc.set_facts(ctx, db, team, d, {"duplicate_of": a.id, "internal_ref": "#2002"})
    again = await triage.import_rows(ctx, db, pair)
    assert (d.duplicate_of, d.internal_ref) == (a.id, "#2002")
    assert again["updated"] == 0 and again["facts_kept"] == 1

    # a patch link: the sheet adds one the ticket does not have and rewrites none it has
    linked = row("916", **tracked, patches=[triage.PatchToken(xe, "55", "sheet")], internal_fix_prs=["#56"])
    first = await triage.import_rows(ctx, db, [linked])
    e = await triage._find(db, linked)
    links = {p.ref: p for p in await thread.patches_for(db, e)}
    assert first["patches"] == 2 and (links["55"].note, links["56"].state) == ("sheet", "merged")
    links["55"].note, links["56"].state = "written by hand", "closed"
    await db.flush()
    again = await triage.import_rows(ctx, db, [linked])
    assert again["patches"] == 0 and len(await thread.patches_for(db, e)) == 2
    assert (links["55"].note, links["56"].state) == ("written by hand", "closed")

    # an award of nothing needs no tier; the sheet's tier is not slipped in behind it, which took the
    # approval back on a patched ticket and stopped the whole run on an awarded one
    untiered = dict(tracked, assessed_tier=None)
    f = await started("917", **untiered)
    assert f.status == "accepted" and f.assessed_tier is None
    await tsvc.set_status(ctx, db, team, f, "patched")
    await tsvc.set_award(ctx, db, team, f, 0, approve=True)
    for st in ("patched", "awarded"):
        if f.status != st:
            await tsvc.set_status(ctx, db, team, f, st)
        again = await triage.import_rows(ctx, db, [row("917", **tracked)])
        assert (f.status, f.assessed_tier) == (st, None) and f.award_approved_at is not None, st
        assert again["updated"] == 0 and again["facts_kept"] == 1, st


async def test_the_export_writes_each_ticket_it_counts_once(ctx, db):  # noqa: F811
    """The rule (XE-2271): the number in the export's heading is the number of rows under it. Asked
    with a ticket in every configured area, one in `other`, one with no area, one whose area the
    configuration does not name, and support tickets (which the triage does not assess)."""

    async def mk(title, area, kind="bounty"):
        return await tsvc.create(ctx, db, "desk", tsvc.NewTicket(kind=kind, title=title, area=area))

    bounty = [await mk(f"Finding in {area}", area) for area in ctx.config.areas]
    retired = await mk("Finding in a retired area", None)
    retired.area = "retired"  # a row stored before the area left the configuration; `create` refuses it
    bounty += [await mk("Finding with no area", None), retired]
    support = [await mk("Question on nodes", "nodes", "support"), await mk("Question", None, "support")]
    assert "other" in ctx.config.areas and len(bounty) == len(ctx.config.areas) + 2
    md = await triage.export_markdown(ctx, db, SYSTEM)
    lines = md.split("\n")
    table = [x for x in lines if x.startswith("| ") and not x.startswith("| # |")]
    assert f"{len(bounty)} tickets." in md and len(table) == len(bounty)
    for t in bounty:
        assert sum(f"| {t.id} | {t.title} |" in x for x in table) == 1, t.title
    for t in support:
        assert t.title not in md and t.id not in md
    headings = [x for x in lines if x.startswith("### ")]
    assert headings == [f"### {label}" for label in ctx.config.areas.values()]
    # Other holds its own ticket and the two that have no section of their own
    at = lines.index("### Other")
    assert all(x.startswith("| ") for x in lines[at + 4:at + 7]) and lines[at + 7] == ""
    # no cell adds a row. A patch link's repo and ref are a repository and a number or sha, and its
    # note is one line, for every writer; a note stored before that was so, and a title that tries
    # to end its own cell, are still written as one cell of one row
    xe = "xeprotocol/xe"
    for bad in ({"repo": "x/y\n| z", "ref": "7"}, {"repo": xe, "ref": "7 | 8"}, {"repo": "xe", "ref": "7"}):
        with pytest.raises(HTTPException) as e:
            await thread.add_patch_ref(ctx, db, SYSTEM, bounty[2], **bad)
        assert e.value.status_code == 400
    kept = await thread.add_patch_ref(
        ctx, db, SYSTEM, bounty[2], repo="xeprotocol/dao", ref="8", note="two\nlines"
    )
    assert kept.note == "two lines"
    old = await thread.add_patch_ref(ctx, db, SYSTEM, bounty[0], repo=xe, ref="7")
    old.note = "x) |\n| XE-0001 | Forged finding | Valid | **Before** |"
    bounty[1].title = "Ends its cell \\| here | and here"
    await db.flush()
    md = await triage.export_markdown(ctx, db, SYSTEM)
    table = [x for x in md.split("\n") if x.startswith("| ") and not x.startswith("| # |")]
    assert f"{len(bounty)} tickets." in md and len(table) == len(bounty)
    assert "Forged finding" in md and "\n| XE-0001 | Forged" not in md
    # nine cells a row: ten pipes that no backslash escapes
    assert all(len(re.findall(r"(?<!\\)(?:\\\\)*\|", x)) == 10 for x in table)

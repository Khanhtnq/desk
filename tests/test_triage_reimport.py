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
    by_ref = {r.key: r for r in rows}
    row = next(r for r in rows if r.status()[0] == "accepted")
    t = await triage._find(db, by_ref[row.key])
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

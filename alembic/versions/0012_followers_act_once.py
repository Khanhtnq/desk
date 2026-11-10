"""A PR or a tracker issue moves a ticket once per state

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-10

`patch_refs.followed` is the PR state the follower last acted on for the ticket; `tickets.internal_followed`
the tracker issue's, as "<ref>:<state>:<reason>". The same PR or issue read again in that state moves
nothing, so a status a person set afterwards stands until the source changes (XE-2080). PRs already linked
are taken as followed in the state they were last seen in, so the first read after this migration does
not replay them. A tracker issue's last state is not stored anywhere, so it is taken from the log: the
last move the tracker made on a ticket still linked to that issue (accepted while it was open, patched
when it closed as completed). A ticket the tracker never moved, or one whose issue closed with another
reason, has its say once more on its next read, as it did on every read before. Idempotent.

The log holds the tracker's moves, not its reads: an issue that closed, patched its report and was
reopened since is recorded here as still closed, and its next close would not be news. No statement
can know that, so read the tracker in full once, straight after this migration
(`desk import-internal --full`, docs/DEPLOY.md §7): each issue is compared with the guess made here,
and one still in that state replays nothing.
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE patch_refs ADD COLUMN IF NOT EXISTS followed VARCHAR(16) NOT NULL DEFAULT ''")
    op.execute(
        "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS internal_followed VARCHAR(64) NOT NULL DEFAULT ''"
    )
    op.execute("UPDATE patch_refs SET followed = state WHERE kind = 'pr' AND followed = '' AND state <> ''")
    # chr(58) is a colon: a ":word" in the statement would be read as a bind parameter
    op.execute(
        """
        UPDATE tickets t
        SET internal_followed = left(
            t.internal_ref || chr(58) || CASE e.payload->>'to'
                WHEN 'patched' THEN 'closed' || chr(58) || 'completed'
                ELSE 'open' || chr(58)
            END, 64)
        FROM (
            SELECT DISTINCT ON (ref) ref, payload FROM events
            WHERE kind = 'ticket.status' AND left(payload->>'via', 9) = 'internal' || chr(58)
            ORDER BY ref, "index" DESC
        ) e
        WHERE e.ref = t.id AND t.internal_followed = '' AND t.internal_ref <> ''
          AND e.payload->>'to' IN ('patched', 'accepted')
          AND right(e.payload->>'via', length(t.internal_ref)) = t.internal_ref
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE tickets DROP COLUMN IF EXISTS internal_followed")
    op.execute("ALTER TABLE patch_refs DROP COLUMN IF EXISTS followed")

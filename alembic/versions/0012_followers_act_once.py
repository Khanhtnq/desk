"""A PR or a tracker issue moves a ticket once per state

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-10

`patch_refs.followed` is the PR state the follower last acted on for the ticket; `tickets.internal_followed`
the tracker issue's, as "<ref>:<state>:<reason>". The same PR or issue read again in that state moves
nothing, so a status a person set afterwards stands until the source changes (XE-2080). PRs already linked
are taken as followed in the state they were last seen in, so the first read after this migration does
not replay them; a tracker issue's last state is not stored anywhere, so each has its say once more on
its next read, as it did on every read before. Idempotent.
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


def downgrade() -> None:
    op.execute("ALTER TABLE tickets DROP COLUMN IF EXISTS internal_followed")
    op.execute("ALTER TABLE patch_refs DROP COLUMN IF EXISTS followed")

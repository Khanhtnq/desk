"""queued: a report past its reporter's daily cap

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-08

`tickets.queued` marks a report filed beyond the reporter's rolling-day cap (`intake.daily_cap`). It is
kept and read after everything else; a person moving the ticket clears it. Idempotent.
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS queued BOOLEAN NOT NULL DEFAULT FALSE")
    op.execute("CREATE INDEX IF NOT EXISTS ix_tickets_queued ON tickets (queued)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_tickets_queued")
    op.execute("ALTER TABLE tickets DROP COLUMN IF EXISTS queued")

"""what a note checked, and an index for reading across the desk

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-05

`notes.checked` records what the writer looked at (the desk, similar tickets, the tracker, the tree) as
data. The full-text index serves the similar-tickets query over title and body. Idempotent.
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE notes ADD COLUMN IF NOT EXISTS checked JSONB NOT NULL DEFAULT '{}'::jsonb")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_tickets_fts ON tickets "
        "USING GIN (to_tsvector('english', title || ' ' || body))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_tickets_fts")
    op.execute("ALTER TABLE notes DROP COLUMN IF EXISTS checked")

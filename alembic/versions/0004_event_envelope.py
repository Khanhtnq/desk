"""hash envelope version on events

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-04

Events written from now on hash their `public` flag and `ref` into the envelope (v2); the rows already in
the chain stay v1 and verify as they were written. Idempotent, like 0002 and 0003.
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS v INTEGER NOT NULL DEFAULT 1")


def downgrade() -> None:
    op.execute("ALTER TABLE events DROP COLUMN IF EXISTS v")

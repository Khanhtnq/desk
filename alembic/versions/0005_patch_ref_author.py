"""who opened a linked PR, and where the ticket was before it moved

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-05

A PR's author is recorded so the sync can tell a maintainer's fix from a stranger's fork PR, and the status
a ticket held before a PR moved it is kept so closing that PR unmerged puts the ticket back where it was
rather than at `accepted`. Idempotent, like the earlier ones.
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE patch_refs ADD COLUMN IF NOT EXISTS author VARCHAR(128) NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE patch_refs ADD COLUMN IF NOT EXISTS moved_from VARCHAR(16) NOT NULL DEFAULT ''")


def downgrade() -> None:
    op.execute("ALTER TABLE patch_refs DROP COLUMN IF EXISTS moved_from")
    op.execute("ALTER TABLE patch_refs DROP COLUMN IF EXISTS author")

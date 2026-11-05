"""the reply draft a ticket is carrying

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-05

An adopted `reply_draft` proposal used to live only in the browser's editor and was lost on refresh. It is
kept on the ticket until a reply is sent. Idempotent, like the earlier ones.
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS draft TEXT NOT NULL DEFAULT ''")


def downgrade() -> None:
    op.execute("ALTER TABLE tickets DROP COLUMN IF EXISTS draft")

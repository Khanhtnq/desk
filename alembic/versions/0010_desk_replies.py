"""A reply may be the desk's own

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-09

`replies.author_id` is null for a reply the desk sends itself: the stock template for a ticket that has
rested at accepted or patched with its reporter untold (`services.tell`). A person's reply still
carries the person. Idempotent.
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE replies ALTER COLUMN author_id DROP NOT NULL")


def downgrade() -> None:
    # rows the desk wrote have no person to point at; they are left as they are
    pass

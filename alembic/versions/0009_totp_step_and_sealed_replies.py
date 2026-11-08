"""TOTP codes are single-use; replies on private tickets are sealed

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-08

`users.totp_last_step` records the last RFC 6238 time step a code was accepted at, so the same code is
not accepted twice (XE-0820). `replies.body_sealed` holds a reply written on a private ticket, sealed with
the vault key like the thread copy; `body` is empty for those rows (XE-0426). Idempotent.
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE replies ADD COLUMN IF NOT EXISTS body_sealed BYTEA")


def downgrade() -> None:
    op.execute("ALTER TABLE replies DROP COLUMN IF EXISTS body_sealed")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS totp_last_step")

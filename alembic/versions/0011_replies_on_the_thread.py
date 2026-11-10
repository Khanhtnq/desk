"""Every reply is on its ticket's thread

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-10

A reply now goes onto the thread when it is sent (`thread.add_reply`), and takes the channel's id for it
when the channel carries it (`thread.reply_carried`). Before this, a reply bound for GitHub or a chat
thread reached the desk's thread only once the mirror succeeded, so one whose mirror failed, was still
queued, or was pulled back when the ticket went private was readable nowhere. Those get their row here:
the reply's own words, name and time. A mirrored reply already has its row under the channel's id. A
plain reply on a private ticket (none should exist) is left out rather than written unsealed. Idempotent.
"""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        INSERT INTO messages
            (ticket_id, source, source_ref, author, author_is_team, body, body_sealed, created_at)
        SELECT r.ticket_id, 'desk', 'reply:' || r.id, r.author_name, true, r.body, r.body_sealed,
               r.created_at
        FROM replies r
        JOIN tickets t ON t.id = r.ticket_id
        WHERE r.mirror <> 'sent'
          AND NOT (t.visibility = 'private' AND r.body_sealed IS NULL)
          AND NOT EXISTS (
              SELECT 1 FROM messages m WHERE m.source = 'desk' AND m.source_ref = 'reply:' || r.id
          )
        """
    )


def downgrade() -> None:
    # the rows are the thread's now; nothing tells a backfilled one from one written on sending
    pass

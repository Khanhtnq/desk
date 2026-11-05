"""ORM tables.

Everything that matters is an event in `events` (the chained log). The other tables are the
current-state projections the UI and API read from. One ticket table, two kinds (bounty, support),
exactly the fields in docs/DESK_BRIEF.md §5, so the triage imports without translation.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

# ---- vocabularies (the config file is the public statement of these; the code enforces them) ---------

KINDS = ("bounty", "support")
VISIBILITIES = ("public", "private")
SOURCES = ("web", "github", "email", "discord", "telegram")
AREAS = (
    "consensus",
    "p2p-sync",
    "node-api",
    "leasing-ledger",
    "dao-harness",
    "sdk-docs-web",
    "ops-testnet",
    "other",
)
# Support questions are filed under a topic, not an engineering area: the people asking hold XE or want to,
# and sort their questions by what they are trying to do. Stored in the same `area` column.
TOPICS = (
    "getting-started",
    "launch-token",
    "wallet-keys",
    "sending-receiving",
    "nodes",
    "testnet-faucet",
    "safety",
    "other",
)
TIERS = ("critical", "severe", "high", "medium", "minor", "none")
VERDICTS = (
    "valid",
    "likely-valid",
    "design-gap",
    "duplicate",
    "notice",
    "support",
    "invalid",
    "out-of-scope",
)
GATES = ("before", "decide", "later")
EFFORTS = ("<1h", "1-4h", "half-1d", "1-3d", "3-5d", "1-2w", "design")
STATUSES = (
    "new",
    "triaging",
    "needs-info",
    "accepted",
    "fixing",
    "patched",
    "disclosed",
    "awarded",
    "paid",
    "closed",
)
CLOSED_REASONS = ("duplicate", "invalid", "out-of-scope", "withdrawn", "answered", "stale")
PROPOSAL_FIELDS = (
    "assessed_tier",
    "verdict",
    "duplicate_of",
    "internal_ref",
    "mainnet_gate",
    "effort_eng",
    "area",
    "status",
    "reply_draft",
    "award_xe",   # whole XE; adopting needs the treasurer role, like setting the award directly
)
AGENT_SCOPES = ("read:public", "read:private", "write:notes", "write:proposals", "write:patch-refs")
ROLES = ("reviewer", "tier", "treasurer", "admin")


# ---- the chained log --------------------------------------------------------------------------------


class Event(Base):
    """Append-only, hash-chained. hash = sha256(canonical json of {index, ts, kind, actor, payload, prev_hash})."""

    __tablename__ = "events"
    index: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)  # unix ns
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(
        String(128), nullable=False
    )  # user:<id>, token:<id>, reporter:<id>, desk
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    signer: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    signature: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    ref: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)  # ticket id, mostly
    v: Mapped[int] = mapped_column(Integer, nullable=False, default=2, server_default="1")  # hash envelope


class LogHead(Base):
    __tablename__ = "log_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    index: Mapped[int] = mapped_column(BigInteger, nullable=False, default=-1)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)


class Anchor(Base):
    """A head snapshot offered for anchoring. The desk holds no state-chain key; the DAO harness or a
    member writes `desk.anchor.<n>` and the reference is recorded here afterwards."""

    __tablename__ = "anchors"
    n: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    event_index: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    statechain_index: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    statechain_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ---- people -----------------------------------------------------------------------------------------


class User(Base):
    """A team account: Reviewer, Treasurer, Admin, and the `tier` right. Signs in with a passkey or TOTP."""

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    roles: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)  # subset of ROLES
    totp_secret: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # sealed by the vault
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Passkey(Base):
    __tablename__ = "passkeys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    transports: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Session(Base):
    """A browser session. The cookie carries a random token; its sha256 is stored here, so a database
    read never yields a usable cookie. Revocable by deletion."""

    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    csrf: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(String(256), nullable=False, default="")


class Invite(Base):
    """One-time links: a new team member's first sign-in, a magic link, a passkey enrolment."""

    __tablename__ = "invites"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)  # invite | magic-link
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Challenge(Base):
    """WebAuthn challenges in flight, keyed by a random id the browser echoes back. Short-lived."""

    __tablename__ = "challenges"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # register | login | totp | oauth
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AgentToken(Base):
    """A scoped bearer token bound to a human owner and a model. Every write it makes is recorded against
    both. The secret is shown once; only its hash is stored."""

    __tablename__ = "agent_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)  # first chars, for display
    owner_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    model_id: Mapped[str] = mapped_column(String(128), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    scopes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)  # subset of AGENT_SCOPES
    # the owner's standing instructions to this agent, returned by GET /v1/me and folded into its brief
    instructions: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SeenSignature(Base):
    """Signed-request replay protection, persisted (the #51 lesson: a RAM FIFO forgets on restart).
    Rows older than the skew window are purged by the worker."""

    __tablename__ = "seen_signatures"
    signature: Mapped[str] = mapped_column(String(128), primary_key=True)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)


class Reporter(Base):
    """Whoever filed. Imported GitHub logins are reporters before anyone signs in; an account claims them."""

    __tablename__ = "reporters"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    github_login: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    github_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, unique=True)
    email: Mapped[str] = mapped_column(String(256), nullable=False, default="", index=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    # The payout address, proven: the reporter signed {"address": xe_address} under xe/desk/payout/v1
    # with the key that derives to it. payout_proof keeps the pub key, signature and timestamp.
    xe_address: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    payout_proof: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Addresses this reporter has signed in with (xe/desk/login/v1); the first becomes the account's key.
    xe_login_addresses: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    platform_ids: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict
    )  # discord/telegram ids (R3)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ReporterSession(Base):
    """A reporter's browser session; same shape as the team's, a different cookie and table so that
    neither can ever be mistaken for the other."""

    __tablename__ = "reporter_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    reporter_id: Mapped[int] = mapped_column(Integer, ForeignKey("reporters.id"), nullable=False, index=True)
    csrf: Mapped[str] = mapped_column(String(64), nullable=False)
    how: Mapped[str] = mapped_column(String(16), nullable=False, default="")  # github | email | xe
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class ReporterLink(Base):
    """A one-time email link for reporters: sign in, or add an email to an account. Fifteen minutes."""

    __tablename__ = "reporter_links"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    reporter_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("reporters.id"), nullable=True)
    next_path: Mapped[str] = mapped_column(String(256), nullable=False, default="/my")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---- tickets ----------------------------------------------------------------------------------------


class IdCounter(Base):
    __tablename__ = "id_counters"
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    next: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class Ticket(Base):
    __tablename__ = "tickets"
    # updated_at is set by the database on UPDATE. Without this, SQLAlchemy expires it at flush and the
    # first read after commit (to_dict in the status/award/facts routes) tries an implicit refresh, which an
    # async session cannot do: MissingGreenlet, a 500 after the write has already landed. RETURNING instead.
    __mapper_args__ = {"eager_defaults": True}
    # One ticket per external thing (github issue, email message id). Tickets filed on the desk itself
    # have no external ref, so the index is partial: rows with an empty source_ref are not constrained.
    __table_args__ = (
        Index(
            "uq_ticket_source",
            "source",
            "source_repo",
            "source_ref",
            unique=True,
            postgresql_where=text("source_ref <> ''"),
        ),
    )
    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # XE-0142 / XS-0031
    kind: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    visibility: Mapped[str] = mapped_column(String(8), nullable=False, default="public")
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    source_repo: Mapped[str] = mapped_column(String(128), nullable=False, default="")  # owner/repo for github
    source_ref: Mapped[str] = mapped_column(
        String(128), nullable=False, default=""
    )  # issue number, thread id
    source_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    reporter_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("reporters.id"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")  # empty when private
    body_sealed: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )  # vault ciphertext when private
    body_editable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # bounty fields
    area: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    claimed_tier: Mapped[str | None] = mapped_column(String(16), nullable=True)
    assessed_tier: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    duplicate_of: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mainnet_gate: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    effort_eng: Mapped[str | None] = mapped_column(String(8), nullable=True)
    internal_ref: Mapped[str] = mapped_column(String(32), nullable=False, default="", index=True)
    disclosed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    award_xe: Mapped[int | None] = mapped_column(BigInteger, nullable=True)  # micro-units
    award_approved_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    award_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payout_address: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    paid_ref: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    # workflow
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new", index=True)
    closed_reason: Mapped[str | None] = mapped_column(String(16), nullable=True)
    assignee_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    github_state: Mapped[str] = mapped_column(
        String(8), nullable=False, default=""
    )  # open | closed, as last seen
    github_labels: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    channel_state: Mapped[str] = mapped_column(
        String(8), nullable=False, default=""
    )  # open | closed, as last mirrored to a chat channel (discord, telegram)
    last_public_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # last reply we sent
    # The reply the team is composing: an adopted agent draft waits here until a reply is sent, so a
    # refresh or a second reviewer finds it in the editor. Team-only; never shown outside the full view.
    draft: Mapped[str] = mapped_column(Text, nullable=False, default="")
    told_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # status told publicly
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    source_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_private(self) -> bool:
        return self.visibility == "private"

    @property
    def is_open(self) -> bool:
        return self.status not in ("closed", "paid")


class Message(Base):
    """The public thread: imported issue comments, reporter messages, and our mirrored replies."""

    __tablename__ = "messages"
    __table_args__ = (UniqueConstraint("source", "source_ref", name="uq_message_source"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(String(16), ForeignKey("tickets.id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # github | web | email | desk
    source_ref: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    author: Mapped[str] = mapped_column(String(128), nullable=False, default="")  # login, email, or user name
    author_is_team: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_sealed: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Note(Base):
    """Internal. Author is a human or an agent token. Never shown to reporters, never mirrored."""

    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(String(16), ForeignKey("tickets.id"), nullable=False, index=True)
    author: Mapped[str] = mapped_column(String(128), nullable=False)  # user:<id> | token:<id>
    author_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Reply(Base):
    """Public. Human author only. Mirrored to the source channel by the worker."""

    __tablename__ = "replies"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(String(16), ForeignKey("tickets.id"), nullable=False, index=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    author_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    mirror: Mapped[str] = mapped_column(
        String(16), nullable=False, default="queued"
    )  # queued | sent | failed | none
    mirror_ref: Mapped[str] = mapped_column(String(256), nullable=False, default="")  # comment url
    mirror_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Proposal(Base):
    """Agent-authored change to a ticket field. Adopting writes the field and an event."""

    __tablename__ = "proposals"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(String(16), ForeignKey("tickets.id"), nullable=False, index=True)
    token_id: Mapped[int] = mapped_column(Integer, ForeignKey("agent_tokens.id"), nullable=False)
    field: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)  # {"value": ...}
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    decided_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PatchRef(Base):
    __tablename__ = "patch_refs"
    __table_args__ = (UniqueConstraint("ticket_id", "repo", "ref", name="uq_patch_ref"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(String(16), ForeignKey("tickets.id"), nullable=False, index=True)
    repo: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(8), nullable=False, default="pr")  # pr | commit
    ref: Mapped[str] = mapped_column(String(64), nullable=False)  # number or sha
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    note: Mapped[str] = mapped_column(String(128), nullable=False, default="")  # "partial", "wrong repo", ...
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="")  # open | merged | closed
    added_by: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    author: Mapped[str] = mapped_column(String(128), nullable=False, default="")  # GitHub login, PRs only
    # the status the ticket held before this PR moved it, so closing the PR unmerged can put it back
    moved_from: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Attachment(Base):
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ticket_id: Mapped[str] = mapped_column(String(16), ForeignKey("tickets.id"), nullable=False, index=True)
    n: Mapped[int] = mapped_column(Integer, nullable=False)  # 1-based within the ticket
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False, default="application/octet-stream")
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    blob_path: Mapped[str] = mapped_column(String(256), nullable=False)
    sealed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ---- integrations -----------------------------------------------------------------------------------


class SyncCursor(Base):
    __tablename__ = "sync_cursors"
    __mapper_args__ = {"eager_defaults": True}  # same reason as Ticket: updated_at is server-set on UPDATE
    key: Mapped[str] = mapped_column(String(128), primary_key=True)  # github:owner/repo:issues
    value: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class SeenDelivery(Base):
    """Webhook delivery ids, so a redelivered event is applied once."""

    __tablename__ = "seen_deliveries"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScheduleRun(Base):
    __tablename__ = "schedule_runs"
    job: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_run_ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class HealthCheck(Base):
    __tablename__ = "health_checks"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False)


Index("ix_events_kind_index", Event.kind, Event.index)
Index("ix_tickets_kind_status", Ticket.kind, Ticket.status)
Index("ix_proposals_ticket_state", Proposal.ticket_id, Proposal.state)

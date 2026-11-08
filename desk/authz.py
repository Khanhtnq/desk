"""Who may do what. One matrix, enforced here, tested in tests/test_authz.py.

An agent recommends; a human decides and speaks. There is no agent scope that sends a reply, sets a
status, sets an award, or reads a payout address. Tier rulings sit with the `tier` role, which any team
member can be given, not with every Reviewer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import HTTPException

from .models import AgentToken, Ticket, User

TEAM_ROLES = ("reviewer", "tier", "treasurer", "admin")

# permission -> (roles that grant it for a user, token scopes that grant it for an agent)
# "*" among roles means any team member (a user holding at least one role).
MATRIX: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "read:public": (
        ("*",),
        ("read:public", "read:private", "write:notes", "write:proposals", "write:patch-refs"),
    ),
    "read:private": (("*",), ("read:private",)),
    # the working layer (notes, proposals, the assessment as it changes) is for tokens that read or take
    # part in it; a token that only links patches does not see it (XE-0696)
    "read:notes": (("*",), ("read:public", "read:private", "write:notes", "write:proposals")),
    "read:payout_address": (("*",), ()),
    "write:notes": (("*",), ("write:notes",)),
    "write:proposals": ((), ("write:proposals",)),
    "write:patch-refs": (("*",), ("write:patch-refs",)),
    "facts": (("*",), ()),  # verdict, duplicate_of, gate, effort, area, internal_ref, assignee
    "tier": (("tier",), ()),  # assessed_tier
    "status": (("*",), ()),
    "reply": (("*",), ()),
    "adopt": (("*",), ()),  # adopting a tier proposal additionally needs "tier"
    "award": (("treasurer",), ()),
    "export:payouts": (("treasurer",), ()),
    "admin": (("admin",), ()),
    "tokens:issue": (("*",), ()),  # a team member may issue tokens bound to themselves
}

FACT_FIELDS = (
    "verdict",
    "duplicate_of",
    "mainnet_gate",
    "effort_eng",
    "area",
    "internal_ref",
    "assignee_id",
    "claimed_tier",
    "visibility",
)
TIER_FIELDS = ("assessed_tier",)


@dataclass
class Principal:
    kind: str = "anon"  # anon | user | token | reporter
    user: User | None = None
    token: AgentToken | None = None
    roles: set[str] = field(default_factory=set)
    scopes: set[str] = field(default_factory=set)
    reporter_id: int | None = None

    @property
    def actor(self) -> str:
        if self.kind == "user" and self.user:
            return f"user:{self.user.id}"
        if self.kind == "token" and self.token:
            return f"token:{self.token.id}"
        if self.kind == "reporter" and self.reporter_id:
            return f"reporter:{self.reporter_id}"
        if self.kind == "system":
            return "desk"
        return "anon"

    @property
    def name(self) -> str:
        """How the principal is named on what it writes; fits the 128-char author columns (XE-1028)."""
        if self.kind == "user" and self.user:
            return (self.user.name or self.user.email)[:128]
        if self.kind == "token" and self.token:
            return f"{self.token.model_id} ({self.token.label or self.token.prefix})"[:128]
        return self.kind

    @property
    def is_team(self) -> bool:
        return self.kind == "user" and bool(self.roles)

    @property
    def is_agent(self) -> bool:
        return self.kind == "token"


ANON = Principal()
# the worker and the CLI act as the desk itself: every role, no token. Used only server-side.
SYSTEM = Principal(kind="system", roles={"admin", "reviewer", "tier", "treasurer"})


def can(p: Principal, permission: str, ticket: Ticket | None = None) -> bool:
    roles, scopes = MATRIX.get(permission, ((), ()))
    ok = False
    if p.kind == "system":
        ok = True
    elif p.kind == "user" and p.roles:
        ok = "*" in roles or bool(p.roles & set(roles))
    elif p.kind == "token" and p.scopes:
        ok = bool(p.scopes & set(scopes))
    elif p.kind == "reporter":
        ok = permission == "read:public" or (
            permission == "read:private" and ticket is not None and ticket.reporter_id == p.reporter_id
        )
    else:
        ok = permission == "read:public"
    if not ok:
        return False
    if ticket is not None and ticket.visibility == "private" and permission.startswith("read:"):
        if permission == "read:public":
            # a private ticket is not public, whoever asks
            return can(p, "read:private", ticket)
    return True


def can_see(p: Principal, ticket: Ticket) -> bool:
    return can(p, "read:private", ticket) if ticket.visibility == "private" else can(p, "read:public", ticket)


def can_set_field(p: Principal, field_name: str) -> bool:
    if field_name in TIER_FIELDS:
        return can(p, "tier")
    if field_name in FACT_FIELDS:
        return can(p, "facts")
    if field_name == "status":
        return can(p, "status")
    return False


def require(p: Principal, permission: str, ticket: Ticket | None = None) -> None:
    if ticket is not None and not can_see(p, ticket):
        raise HTTPException(404, "no such ticket")
    if not can(p, permission, ticket):
        if p.kind == "anon":
            raise HTTPException(401, "sign in, or send a bearer token")
        raise HTTPException(403, f"{p.kind} may not {permission}")


def require_field(p: Principal, field_name: str) -> None:
    if not can_set_field(p, field_name):
        if field_name in TIER_FIELDS:
            raise HTTPException(403, "tier rulings need the tier role")
        raise HTTPException(403, f"may not set {field_name}")

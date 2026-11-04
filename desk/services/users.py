"""Team accounts and agent tokens."""

from __future__ import annotations

import re

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import auth
from ..authz import Principal
from ..context import Context
from ..models import ROLES, AgentToken, Passkey, User
from .tickets import utcnow


EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


async def by_email(db: AsyncSession, email: str) -> User | None:
    return (await db.execute(select(User).where(User.email == email.strip().lower()))).scalar_one_or_none()


async def by_id(db: AsyncSession, uid: int) -> User | None:
    return (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()


async def list_users(db: AsyncSession) -> list[User]:
    return list((await db.execute(select(User).order_by(User.id.asc()))).scalars().all())


async def create_user(
    ctx: Context, db: AsyncSession, actor: str, email: str, name: str, roles: list[str]
) -> User:
    email = email.strip().lower()
    if "@" not in email:
        raise HTTPException(400, "email looks wrong")
    bad = [r for r in roles if r not in ROLES]
    if bad:
        raise HTTPException(400, f"unknown roles {bad}; choose from {list(ROLES)}")
    if await by_email(db, email):
        raise HTTPException(409, "that email already has an account")
    u = User(email=email, name=name.strip()[:128], roles=sorted(set(roles)))
    db.add(u)
    await db.flush()
    await ctx.events.append(db, "user.created", actor, {"user": u.id, "email": email, "roles": u.roles})
    return u


async def set_roles(ctx: Context, db: AsyncSession, actor: str, u: User, roles: list[str]) -> None:
    bad = [r for r in roles if r not in ROLES]
    if bad:
        raise HTTPException(400, f"unknown roles {bad}")
    old = list(u.roles)
    u.roles = sorted(set(roles))
    await ctx.events.append(db, "user.roles", actor, {"user": u.id, "from": old, "to": u.roles})
    if not u.roles:
        await revoke_all(ctx, db, actor, u, why="roles removed")


async def set_name(ctx: Context, db: AsyncSession, actor: str, u: User, name: str) -> None:
    """The name on every reply this person sends. Changing it changes future replies only; past ones
    keep the name they were sent under."""
    name = " ".join((name or "").split())
    if not 1 <= len(name) <= 128:
        raise HTTPException(400, "a name is 1 to 128 characters")
    old = u.name
    u.name = name
    await ctx.events.append(db, "user.renamed", actor, {"user": u.id, "from": old, "to": name})


async def set_email(ctx: Context, db: AsyncSession, actor: str, u: User, email: str) -> None:
    """The sign-in email and where invites go. Must be unused by another member."""
    email = (email or "").strip().lower()
    if not EMAIL.match(email) or len(email) > 256:
        raise HTTPException(400, "that does not look like an email address")
    other = await by_email(db, email)
    if other is not None and other.id != u.id:
        raise HTTPException(409, "another member has that email")
    old = u.email
    if old == email:
        return
    u.email = email
    await ctx.events.append(db, "user.email", actor, {"user": u.id, "from": old, "to": email})


async def set_active(ctx: Context, db: AsyncSession, actor: str, u: User, active: bool) -> None:
    u.active = active
    await ctx.events.append(db, "user.active", actor, {"user": u.id, "active": active})
    if not active:
        await revoke_all(ctx, db, actor, u, why="owner deactivated")


async def revoke_all(ctx: Context, db: AsyncSession, actor: str, u: User, *, why: str) -> int:
    """Every live token of a person who is no longer on the team stops with them. Returns how many."""
    q = select(AgentToken).where(AgentToken.owner_id == u.id, AgentToken.revoked_at.is_(None))
    n = 0
    for t in (await db.execute(q)).scalars().all():
        t.revoked_at = utcnow()
        await ctx.events.append(db, "token.revoked", actor, {"token": t.id, "owner": u.id, "why": why})
        n += 1
    return n


async def passkeys_for(db: AsyncSession, u: User) -> list[Passkey]:
    return list(
        (await db.execute(select(Passkey).where(Passkey.user_id == u.id).order_by(Passkey.created_at.asc())))
        .scalars()
        .all()
    )


async def token_owners(db: AsyncSession) -> dict[int, str]:
    """Token id -> the name of the human it belongs to. Resolved at read time, so it covers every note and
    proposal ever written and follows renames."""
    q = select(AgentToken.id, User.name, User.email).join(User, User.id == AgentToken.owner_id)
    rows = await db.execute(q)
    return {tid: (name or email) for tid, name, email in rows.all()}


async def tokens_for(db: AsyncSession, u: User | None = None) -> list[AgentToken]:
    q = select(AgentToken).order_by(AgentToken.created_at.desc())
    if u is not None:
        q = q.where(AgentToken.owner_id == u.id)
    return list((await db.execute(q)).scalars().all())


async def token_by_id(db: AsyncSession, tid: int) -> AgentToken | None:
    return (await db.execute(select(AgentToken).where(AgentToken.id == tid))).scalar_one_or_none()


async def issue(
    ctx: Context,
    db: AsyncSession,
    p: Principal,
    owner: User,
    model_id: str,
    label: str,
    scopes: list[str],
    days: int,
    instructions: str = "",
) -> tuple[AgentToken, str]:
    if p.user is None:
        raise HTTPException(403, "tokens are issued by a signed-in person")
    if owner.id != p.user.id and "admin" not in p.roles:
        raise HTTPException(403, "only an admin issues a token for someone else")
    if "read:private" in scopes and not p.roles:
        raise HTTPException(403, "read:private can only be granted by a team member")
    t, raw = await auth.issue_token(db, owner, model_id, label, scopes, days, instructions)
    await ctx.events.append(
        db,
        "token.issued",
        p.actor,
        {
            "token": t.id,
            "owner": owner.id,
            "model": t.model_id,
            "label": t.label,
            "scopes": t.scopes,
            "expires_at": t.expires_at.isoformat(),
        },
    )
    return t, raw


async def revoke(ctx: Context, db: AsyncSession, p: Principal, t: AgentToken) -> None:
    if p.user is None or (t.owner_id != p.user.id and "admin" not in p.roles):
        raise HTTPException(403, "only the owner or an admin revokes a token")
    if t.revoked_at is None:
        t.revoked_at = utcnow()
        await ctx.events.append(db, "token.revoked", p.actor, {"token": t.id, "owner": t.owner_id})


async def set_instructions(ctx: Context, db: AsyncSession, p: Principal, t: AgentToken, text: str) -> None:
    """The owner (or an admin) changes what their agent is told. Logged; the next GET /v1/me carries it."""
    if p.user is None or (t.owner_id != p.user.id and "admin" not in p.roles):
        raise HTTPException(403, "only the token's owner or an admin sets its instructions")
    t.instructions = (text or "").strip()[:4000]
    await ctx.events.append(
        db, "token.instructed", p.actor, {"token": t.id, "chars": len(t.instructions)}, public=False
    )


def token_dict(t: AgentToken) -> dict:
    return {
        "id": t.id,
        "prefix": t.prefix,
        "owner_id": t.owner_id,
        "model_id": t.model_id,
        "label": t.label,
        "scopes": t.scopes,
        "instructions": t.instructions,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "expires_at": t.expires_at.isoformat(),
        "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
    }


def user_dict(u: User) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "name": u.name,
        "roles": u.roles,
        "active": u.active,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    }

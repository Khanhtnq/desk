"""Who is asking.

Three ways in, none of them a password:

  team      a passkey (WebAuthn, RP id shared by both front doors) or a TOTP code; the session is a
            random cookie whose hash lives in `sessions`, so it can be revoked and a database read
            never yields a usable cookie. First sign-in is a one-time invite link.
  agent     a bearer token, `desk_...`, bound to a human owner, a model id, scopes and an expiry.
  reporter  GitHub OAuth, an email link, or an XE key signature in the harness's signed-request shape
            under `xe/desk/login/v1`. Its own cookie and table (`reporter_sessions`), so a reporter session
            can never be read as a team one. The routes are in api/reporter.py.

A write from a browser session, the team's or a reporter's, carries that session's CSRF token in
`X-Desk-CSRF`; the check is made once, for every route, in `api/deps.current`. Cookies are SameSite=Lax.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import smtplib
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from xe.keys import KeyError_, derive_address, verify_hex_signature

from .authz import Principal
from .canonical import digest, same_secret
from .models import (
    AGENT_SCOPES,
    AgentToken,
    Challenge,
    Invite,
    Passkey,
    Reporter,
    ReporterLink,
    ReporterSession,
    SeenSignature,
    Session,
    User,
)
from .settings import Settings

log = logging.getLogger("desk.auth")

SESSION_COOKIE = "desk_session"
REPORTER_COOKIE = "desk_reporter"
SESSION_TTL = timedelta(days=14)
INVITE_TTL = timedelta(days=7)
MAGIC_TTL = timedelta(minutes=15)
CHALLENGE_TTL = timedelta(minutes=5)
TOKEN_PREFIX = "desk_"
MAX_SKEW_NS = 10 * 60 * 1_000_000_000


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_secret(raw: str) -> str:
    return hashlib.sha256(clean_lookup(raw).encode("utf-8")).hexdigest()


def clean_lookup(raw: str | None, limit: int = 256) -> str:
    """A value about to be looked up or hashed: no NUL, no lone surrogates, bounded. Postgres and
    `str.encode` both raise on those and the request would end as a bare 500 (XE-0827); a value with
    them in it matches nothing, which is what the empty string does."""
    s = raw or ""
    if "\x00" in s:
        return ""
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return ""
    return s[:limit]


def unstorable(value: Any) -> bool:
    """A NUL or half a surrogate pair anywhere in parsed JSON: any string, any key, at any depth
    (walked without recursion). Postgres stores neither, as text or inside jsonb."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if "\x00" in v:
                return True
            try:
                v.encode("utf-8")
            except UnicodeEncodeError:
                return True
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return False


class Body(BaseModel):
    """The base of every JSON request body. Postgres refuses a NUL in text and in jsonb, and half a
    surrogate pair (which JSON can spell: "\\udc80") cannot be encoded to send at all; a request that
    carried either into a statement ended as a bare 500 (XE-0827, XE-1426, XE-1015). The cleaning
    was at the call sites that remembered it; the rule is here, at the boundary, for every field of
    every body including the free-form ones (a facts dict, a proposal's value): such a body is a 422.
    Refused, not stripped: stripping gives `XE-0\x00142` and `XE-0142` one meaning. The path and the
    query string are `main.NoNul`'s (neither can carry a lone surrogate: both are decoded with
    replacement); form fields are cleaned where they are read."""

    @model_validator(mode="before")
    @classmethod
    def _refuse_unstorable(cls, data: Any) -> Any:
        if unstorable(data):
            raise ValueError("the request has a NUL or half a surrogate pair in it")
        return data


_DECOY_KEY = secrets.token_bytes(32)  # per process; see passkey_begin_login


# ---- sessions ---------------------------------------------------------------------------------------


async def create_session(db: AsyncSession, user: User, request: Request | None = None) -> tuple[Session, str]:
    raw = new_secret()
    s = Session(
        token_hash=hash_secret(raw),
        user_id=user.id,
        csrf=new_secret(24),
        expires_at=now() + SESSION_TTL,
        ip=client_ip(request) if request else "",
        user_agent=(clean_lookup(request.headers.get("user-agent")) if request else ""),
    )
    db.add(s)
    user.last_login_at = now()
    await db.flush()
    return s, raw


async def session_from_request(db: AsyncSession, request: Request) -> tuple[Session, User] | None:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    s = (await db.execute(select(Session).where(Session.token_hash == hash_secret(raw)))).scalar_one_or_none()
    if s is None or s.expires_at < now():
        return None
    u = (await db.execute(select(User).where(User.id == s.user_id))).scalar_one_or_none()
    if u is None or not u.active or not u.roles:
        return None
    return s, u


async def end_session(db: AsyncSession, request: Request) -> None:
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        await db.execute(delete(Session).where(Session.token_hash == hash_secret(raw)))


def set_session_cookie(response: Response, raw: str, settings: Settings, name: str = SESSION_COOKIE) -> None:
    response.set_cookie(
        name,
        raw,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=settings.scheme == "https",
        path="/",
        domain=settings.cookie_domain,
    )


def clear_session_cookie(
    response: Response, settings: Settings | None = None, name: str = SESSION_COOKIE
) -> None:
    response.delete_cookie(name, path="/", domain=settings.cookie_domain if settings else None)


# ---- reporter sessions and links ----------------------------------------------------------------------


async def create_reporter_session(
    db: AsyncSession, r: Reporter, how: str, request: Request | None = None
) -> tuple[ReporterSession, str]:
    raw = new_secret()
    s = ReporterSession(
        token_hash=hash_secret(raw),
        reporter_id=r.id,
        csrf=new_secret(24),
        how=how,
        expires_at=now() + SESSION_TTL,
        ip=client_ip(request) if request else "",
    )
    db.add(s)
    r.last_login_at = now()
    if r.claimed_at is None:
        r.claimed_at = now()
    await db.flush()
    return s, raw


async def reporter_session_from_request(
    db: AsyncSession, request: Request
) -> tuple[ReporterSession, Reporter] | None:
    raw = request.cookies.get(REPORTER_COOKIE)
    if not raw:
        return None
    s = (
        await db.execute(select(ReporterSession).where(ReporterSession.token_hash == hash_secret(raw)))
    ).scalar_one_or_none()
    if s is None or s.expires_at < now():
        return None
    r = (await db.execute(select(Reporter).where(Reporter.id == s.reporter_id))).scalar_one_or_none()
    return (s, r) if r else None


async def end_reporter_session(db: AsyncSession, request: Request) -> None:
    raw = request.cookies.get(REPORTER_COOKIE)
    if raw:
        await db.execute(delete(ReporterSession).where(ReporterSession.token_hash == hash_secret(raw)))


def safe_next(settings, nxt: str | None, default: str = "/my") -> str:
    """A post-sign-in destination: a path on this deployment (not protocol-relative, not a backslash
    trick), or an absolute URL on one of its hosts. Anything else is the default."""
    if not nxt or any(c in nxt for c in "\\\r\n\x00") or nxt != nxt.strip():
        # browsers read a backslash as a slash in http(s) URLs while urlsplit does not (XE-1092):
        # nothing with one is a destination we can reason about
        return default
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    u = urlsplit(nxt)
    if u.scheme == settings.scheme and u.hostname in settings.hosts.values() and not u.username:
        return nxt
    return default


async def create_reporter_link(
    db: AsyncSession, email: str, reporter_id: int | None, next_path: str = "/my"
) -> str:
    raw = new_secret()
    db.add(
        ReporterLink(
            token_hash=hash_secret(raw),
            email=email.lower(),
            reporter_id=reporter_id,
            next_path=next_path[:256],
            expires_at=now() + MAGIC_TTL,
        )
    )
    await db.flush()
    return raw


async def family_lock(db: AsyncSession, key: str) -> None:
    """A transaction-scoped advisory lock, held to commit: whoever is about to write several rows that
    belong to one owner (an address's sign-in links, a member's invites, a reporter being looked up
    and perhaps created) takes the owner's lock first, so two of them queue instead of each holding
    a row the other wants. Re-entrant within a transaction. Postgres only."""
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": key})


async def consume_reporter_link(db: AsyncSession, raw: str) -> ReporterLink | None:
    """Single use, atomically: the row is claimed with one conditional UPDATE, so two concurrent
    consumers of one link cannot both sign in (XE-0709). Consuming a link also burns every other
    outstanding link for the same address: the person has recovered, older mail is not a credential
    any more (XE-0782). The address's lock is taken before either write: two sibling links used in the
    same moment each claimed its own row and then waited for the other's to burn it, and the database
    ended the deadlock with an error, a 500 where one of them should have signed in and the other
    been told the link was used (XE-1903). It is the lock a first sign-in with that address takes
    (`reporters.identity_lock`), so the sign-in that follows already holds it."""
    stamp = now()
    q = select(ReporterLink.email).where(ReporterLink.token_hash == hash_secret(raw))
    email = (await db.execute(q)).scalar_one_or_none()
    if email is None:
        return None
    await family_lock(db, f"reporter:email:{email}")
    res = await db.execute(
        update(ReporterLink)
        .where(
            ReporterLink.token_hash == hash_secret(raw),
            ReporterLink.used_at.is_(None),
            ReporterLink.expires_at >= stamp,
        )
        .values(used_at=stamp)
        .returning(ReporterLink.id)
    )
    row = res.first()
    if row is None:
        return None
    link = (await db.execute(select(ReporterLink).where(ReporterLink.id == row[0]))).scalar_one()
    await db.execute(
        update(ReporterLink)
        .where(
            ReporterLink.email == link.email,
            ReporterLink.used_at.is_(None),
            ReporterLink.expires_at >= stamp,  # an expired one is dead already, and is the purge's to take
        )
        .values(used_at=stamp)
    )
    return link


async def drop_reporter_links(db: AsyncSession, *, reporter_id: int | None = None, email: str = "") -> None:
    """Delete the sign-in links bound to an account, and those sent to an address, under the lock of
    every address among them (in order), as the consumer of one takes it: a writer of several of a
    family's rows that does not queue with the others is the other half of a deadlock (XE-1903)."""
    by = []
    if reporter_id is not None:
        by.append(ReporterLink.reporter_id == reporter_id)
    if email:
        by.append(ReporterLink.email == email)
    if not by:
        return
    emails = set((await db.execute(select(ReporterLink.email).where(or_(*by)))).scalars().all())
    for e in sorted(emails | ({email} if email else set())):
        await family_lock(db, f"reporter:email:{e}")
    await db.execute(delete(ReporterLink).where(or_(*by)))


async def purge_reporter_auth(db: AsyncSession) -> int:
    a = await db.execute(delete(ReporterSession).where(ReporterSession.expires_at < now()))
    b = await db.execute(delete(ReporterLink).where(ReporterLink.expires_at < now() - timedelta(days=1)))
    return int(a.rowcount or 0) + int(b.rowcount or 0)


def client_ip(request: Request | None) -> str:
    """Caddy sets X-Forwarded-For with the client first; uvicorn's proxy-headers middleware has already
    rewritten request.client from it. We never read the header ourselves (the #81 lesson)."""
    if request is None or request.client is None:
        return ""
    return request.client.host or ""


def check_csrf(request: Request, session: Session | ReporterSession) -> None:
    sent = request.headers.get("x-desk-csrf", "")
    if not sent or not same_secret(sent, session.csrf):
        raise HTTPException(403, "missing or stale CSRF token; reload the page")


# ---- invites and magic links ------------------------------------------------------------------------


async def create_invite(db: AsyncSession, user: User, purpose: str = "invite") -> str:
    raw = new_secret()
    ttl = INVITE_TTL if purpose == "invite" else MAGIC_TTL
    db.add(Invite(token_hash=hash_secret(raw), user_id=user.id, purpose=purpose, expires_at=now() + ttl))
    await db.flush()
    return raw


async def consume_invite(
    db: AsyncSession, raw: str, purposes: tuple[str, ...] = ("invite", "magic-link")
) -> User | None:
    # one conditional UPDATE claims the row (XE-0837); the user's other outstanding invites and magic
    # links are burned with it (XE-0782), under the member's lock so two of them used at once queue
    # rather than deadlock (XE-1903). The member's lock is the member's row: every team write to a
    # member takes that row first (`member_lock`), and the sign-in that follows this writes it, so
    # an accept and a deactivation queue on it whichever starts first. An advisory lock beside the
    # row was taken after the row by one of them and before it by the other.
    stamp = now()
    owner = (
        await db.execute(select(Invite.user_id).where(Invite.token_hash == hash_secret(raw)))
    ).scalar_one_or_none()
    if owner is None:
        return None
    await member_lock(db, owner)
    res = await db.execute(
        update(Invite)
        .where(
            Invite.token_hash == hash_secret(raw),
            Invite.used_at.is_(None),
            Invite.expires_at >= stamp,
            Invite.purpose.in_(purposes),
        )
        .values(used_at=stamp)
        .returning(Invite.user_id)
    )
    row = res.first()
    if row is None:
        return None
    await db.execute(
        update(Invite)
        .where(Invite.user_id == row[0], Invite.used_at.is_(None), Invite.expires_at >= stamp)
        .values(used_at=stamp)
    )
    u = (await db.execute(select(User).where(User.id == row[0]))).scalar_one_or_none()
    return u if u and u.active and u.roles else None


async def member_lock(db: AsyncSession, user_id: int) -> None:
    """The row lock on a team member, re-read: the owner's lock for the member's invites, and the
    first thing a writer of the member takes. Pending changes are flushed first, as `tickets.lock`."""
    await db.flush()
    q = select(User).where(User.id == user_id).with_for_update()
    await db.execute(q.execution_options(populate_existing=True))


async def drop_invites(db: AsyncSession, user_id: int) -> None:
    """Delete a member's unused invites: the account is deactivated, or the address they were
    mailed to is no longer the member's. The caller holds `member_lock`."""
    await db.execute(delete(Invite).where(Invite.user_id == user_id, Invite.used_at.is_(None)))


# ---- TOTP (RFC 6238, stdlib only) ---------------------------------------------------------------------


def totp_new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp_code(secret_b32: str, at: int | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((at if at is not None else time.time()) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def totp_verify(secret_b32: str, code: str, window: int = 1, after_step: int = 0) -> int | None:
    """The time step the code matches, or None. Only ASCII digits are a code (`str.isdigit` admits
    Unicode digits that `compare_digest` then rejects with a TypeError, XE-1033). A step at or before
    `after_step` is refused, which is how a code becomes single-use (XE-0820): the caller records the
    step it accepted."""
    code = (code or "").strip().replace(" ", "")
    if not code or not all(c in "0123456789" for c in code):
        return None
    step = int(time.time()) // 30
    for i in range(-window, window + 1):
        if same_secret(totp_code(secret_b32, (step + i) * 30), code):
            return step + i if step + i > after_step else None
    return None


def totp_uri(secret_b32: str, email: str, issuer: str) -> str:
    from urllib.parse import quote

    return f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret_b32}&issuer={quote(issuer)}&digits=6&period=30"


# ---- passkeys (WebAuthn) ----------------------------------------------------------------------------


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


async def _store_challenge(db: AsyncSession, kind: str, challenge: bytes, user_id: int | None) -> str:
    cid = new_secret(16)
    db.add(
        Challenge(id=cid, kind=kind, user_id=user_id, challenge=challenge, expires_at=now() + CHALLENGE_TTL)
    )
    await db.flush()
    return cid


@dataclass
class TakenChallenge:
    kind: str
    user_id: int | None
    challenge: bytes
    detail: dict


async def take_challenge(
    db: AsyncSession, cid: str, kind: str, missing: str = "challenge expired; try again"
) -> TakenChallenge:
    """A challenge is used once, and the claim is one statement (XE-2053): DELETE ... RETURNING, so of
    two concurrent finishes of one ceremony the second waits on the first and then finds nothing. Read,
    check, then delete let both read the row before either committed. Every kind is taken here: passkey
    registration and sign-in, TOTP setup, and the OAuth states of the reporter sign-ins. A 400 when
    there is no challenge of that kind under that id, or it has expired."""
    res = await db.execute(
        delete(Challenge)
        .where(Challenge.id == clean_lookup(cid, 64), Challenge.kind == kind, Challenge.expires_at >= now())
        .returning(Challenge.kind, Challenge.user_id, Challenge.challenge, Challenge.detail)
    )
    row = res.first()
    if row is None:
        raise HTTPException(400, missing)
    return TakenChallenge(kind=row[0], user_id=row[1], challenge=row[2], detail=row[3] or {})


async def claim_totp_step(db: AsyncSession, user: User, step: int) -> bool:
    """A code is accepted once (XE-0820), and the claim is one statement (XE-1735): a conditional UPDATE
    moves the member's last accepted step forward, and only the request whose UPDATE moved it signs in.
    Reading the step, comparing and then writing it let two requests with one code both pass."""
    res = await db.execute(
        update(User)
        .where(User.id == user.id, User.totp_last_step < step)
        .values(totp_last_step=step)
        .returning(User.id)
    )
    return res.first() is not None


async def claim_sign_count(db: AsyncSession, pk: Passkey, new: int) -> bool:
    """A passkey's signature counter only moves forward, and recording it is a claim like the TOTP
    step's (the XE-2053 sweep): one conditional UPDATE, so of two sign-ins that both read the old
    count the one behind is refused rather than writing the counter back. An authenticator that
    keeps no counter sends 0 every time; 0 over 0 is accepted, as the library accepts it."""
    forward = Passkey.sign_count < new if new else Passkey.sign_count == 0
    res = await db.execute(
        update(Passkey)
        .where(Passkey.id == pk.id, forward)
        .values(sign_count=new, last_used_at=now())
        .returning(Passkey.id)
    )
    return res.first() is not None


async def passkey_begin_registration(db: AsyncSession, settings: Settings, user: User) -> dict:
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    existing = list((await db.execute(select(Passkey).where(Passkey.user_id == user.id))).scalars().all())
    opts = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=str(user.id).encode("utf-8"),
        user_name=user.email,
        user_display_name=user.name or user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=p.credential_id) for p in existing],
    )
    cid = await _store_challenge(db, "register", opts.challenge, user.id)
    return {"challenge_id": cid, "options": json.loads(options_to_json(opts))}


async def passkey_finish_registration(
    db: AsyncSession, settings: Settings, user: User, challenge_id: str, credential: Any, label: str = ""
) -> Passkey:
    from webauthn import verify_registration_response

    ch = await take_challenge(db, challenge_id, "register")
    if ch.user_id != user.id:
        raise HTTPException(400, "challenge belongs to another sign-in")
    try:
        v = verify_registration_response(
            credential=credential,
            expected_challenge=ch.challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=settings.origins,
        )
    except Exception as e:
        raise HTTPException(400, f"passkey registration failed: {e}") from e
    transports = []
    if isinstance(credential, dict):
        transports = list((credential.get("response") or {}).get("transports") or [])
    pk = Passkey(
        user_id=user.id,
        credential_id=v.credential_id,
        public_key=v.credential_public_key,
        sign_count=v.sign_count,
        transports=transports,
        label=label[:128],
    )
    db.add(pk)
    await db.flush()
    return pk


async def passkey_begin_login(db: AsyncSession, settings: Settings, email: str | None = None) -> dict:
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

    allow = []
    user_id = None
    email = clean_lookup(email)
    if email:
        u = (await db.execute(select(User).where(User.email == email.strip().lower()))).scalar_one_or_none()
        if u and u.active and u.roles:
            user_id = u.id
            keys = list((await db.execute(select(Passkey).where(Passkey.user_id == u.id))).scalars().all())
            allow = [PublicKeyCredentialDescriptor(id=p.credential_id) for p in keys]
        if not allow:
            # the same shape for an unknown address, an inactive member and a member without a passkey,
            # so the list is not a membership oracle (XE-0523): one decoy id, stable per address
            decoy = hmac.new(_DECOY_KEY, email.encode("utf-8"), hashlib.sha256).digest()
            allow = [PublicKeyCredentialDescriptor(id=decoy)]
    opts = generate_authentication_options(
        rp_id=settings.rp_id,
        allow_credentials=allow or None,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    cid = await _store_challenge(db, "login", opts.challenge, user_id)
    return {"challenge_id": cid, "options": json.loads(options_to_json(opts))}


async def passkey_finish_login(
    db: AsyncSession, settings: Settings, challenge_id: str, credential: Any
) -> User:
    from webauthn import verify_authentication_response
    from webauthn.helpers import parse_authentication_credential_json

    ch = await take_challenge(db, challenge_id, "login")
    try:
        parsed = parse_authentication_credential_json(credential)
    except Exception as e:
        raise HTTPException(400, f"malformed credential: {e}") from e
    pk = (
        await db.execute(select(Passkey).where(Passkey.credential_id == parsed.raw_id))
    ).scalar_one_or_none()
    if pk is None:
        raise HTTPException(401, "unknown passkey")
    try:
        v = verify_authentication_response(
            credential=parsed,
            expected_challenge=ch.challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=settings.origins,
            credential_public_key=pk.public_key,
            credential_current_sign_count=pk.sign_count,
        )
    except Exception as e:
        raise HTTPException(401, f"passkey sign-in failed: {e}") from e
    if not await claim_sign_count(db, pk, v.new_sign_count):
        raise HTTPException(401, "passkey sign-in failed: its counter has moved on; try again")
    u = (await db.execute(select(User).where(User.id == pk.user_id))).scalar_one_or_none()
    if u is None or not u.active or not u.roles:
        raise HTTPException(401, "account is not active")
    return u


# ---- agent tokens -----------------------------------------------------------------------------------


async def issue_token(
    db: AsyncSession,
    owner: User,
    model_id: str,
    label: str,
    scopes: list[str],
    days: int = 90,
    instructions: str = "",
) -> tuple[AgentToken, str]:
    bad = [s for s in scopes if s not in AGENT_SCOPES]
    if bad:
        raise HTTPException(400, f"unknown scopes: {bad}")
    if days < 1 or days > 365:
        raise HTTPException(400, "expiry must be 1–365 days")
    raw = TOKEN_PREFIX + new_secret(32)
    t = AgentToken(
        token_hash=hash_secret(raw),
        prefix=raw[:12],
        owner_id=owner.id,
        model_id=model_id[:128],
        label=label[:128],
        scopes=sorted(set(scopes)),
        instructions=instructions.strip()[:4000],
        expires_at=now() + timedelta(days=days),
    )
    db.add(t)
    await db.flush()
    return t, raw


async def token_from_bearer(db: AsyncSession, raw: str) -> AgentToken | None:
    if not raw.startswith(TOKEN_PREFIX):
        return None
    t = (
        await db.execute(select(AgentToken).where(AgentToken.token_hash == hash_secret(raw)))
    ).scalar_one_or_none()
    if t is None or t.revoked_at is not None or t.expires_at < now():
        return None
    if t.last_used_at is None or (now() - t.last_used_at).total_seconds() > 60:
        t.last_used_at = now()
    return t


# ---- the principal dependency -------------------------------------------------------------------------


@dataclass
class Auth:
    principal: Principal
    session: Session | None = None
    reporter_session: ReporterSession | None = None
    reporter: Reporter | None = None

    @property
    def csrf(self) -> str:
        if self.session:
            return self.session.csrf
        if self.reporter_session:
            return self.reporter_session.csrf
        return ""


async def resolve(db: AsyncSession, request: Request) -> Auth:
    """Bearer token first (agents), then the team cookie, then the reporter cookie. Anonymous otherwise.
    A browser holding both cookies is the team member: the team view shows more and never less."""
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        t = await token_from_bearer(db, authz[7:].strip())
        if t is None:
            raise HTTPException(401, "token is unknown, expired or revoked")
        owner = (await db.execute(select(User).where(User.id == t.owner_id))).scalar_one_or_none()
        if owner is None or not owner.active or not owner.roles:
            # a token is an extension of a team member; no roles, no team member, no token
            raise HTTPException(401, "token owner is not an active team member")
        return Auth(Principal(kind="token", token=t, scopes=set(t.scopes)))
    got = await session_from_request(db, request)
    if got:
        s, u = got
        return Auth(Principal(kind="user", user=u, roles=set(u.roles)), session=s)
    rep = await reporter_session_from_request(db, request)
    if rep:
        rs, r = rep
        return Auth(Principal(kind="reporter", reporter_id=r.id), reporter_session=rs, reporter=r)
    return Auth(Principal())


# ---- XE signed requests (release 2 routes; the verifier lives here so it is tested now) ------------------


# Exactly 64 / 128 hex digits, either case, at the request model: the signature is the replay key and the
# key names the account, so each has one accepted spelling (lowercased below) and nothing that is not hex
# reaches the verifier, the replay table or a stored proof. `xe.keys` refuses the same strings on its own,
# for a caller that does not come through this model (XE-2215; XE-0699 was the DAO's copy).
HEX32 = r"^[0-9a-fA-F]{64}$"
HEX64 = r"^[0-9a-fA-F]{128}$"  # the lengths are stated twice below: `$` is not end-of-text in every engine


class SignedRequest(Body):
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: int
    pub_key: str = Field(pattern=HEX32, min_length=64, max_length=64)
    signature: str = Field(pattern=HEX64, min_length=128, max_length=128)

    @field_validator("payload")
    @classmethod
    def _flat(cls, v: dict[str, Any]) -> dict[str, Any]:
        """What the desk asks a key to sign is a few plain values (`{"host": ...}`, `{"address":
        ...}`). The payload is hashed before the signature is checked and read after, and a value
        nested as deep as the parser took it is deeper than either is sure to go: refused here, so
        neither is asked."""
        if len(v) > 16 or any(isinstance(x, (dict, list)) for x in v.values()):
            raise ValueError("a signed payload is a flat object of at most 16 values")
        return v


@dataclass
class Verified:
    account: str
    pub_key: str
    payload: dict
    timestamp: int
    signature: str


def signing_target(domain: bytes, payload: dict, timestamp: int) -> bytes:
    return digest(domain, {"payload": payload, "timestamp": timestamp})


async def verify_signed(db: AsyncSession, req: SignedRequest, domain: bytes) -> Verified:
    t = time.time_ns()
    if abs(t - req.timestamp) > MAX_SKEW_NS:
        raise HTTPException(400, "signature timestamp is outside the ±10 minute window")
    try:
        account = derive_address(req.pub_key)
        verify_hex_signature(req.pub_key, req.signature, signing_target(domain, req.payload, req.timestamp))
    except KeyError_ as e:
        raise HTTPException(401, f"bad signature: {e}") from e
    sig = req.signature.lower()
    if not await claim_first(db, SeenSignature, signature=sig, ts=t):
        raise HTTPException(409, "this signature has already been used")
    return Verified(
        account=account,
        pub_key=req.pub_key.lower(),
        payload=req.payload,
        timestamp=req.timestamp,
        signature=sig,
    )


async def claim_first(db: AsyncSession, model, **values) -> bool:
    """Write the row that marks something as used (a signature, a webhook delivery); False when it is
    already there. One INSERT ... ON CONFLICT DO NOTHING, so of two requests carrying the same one the
    second waits for the first and is then told it was used, where a read followed by an insert let both
    read nothing and the second fail on the primary key as a 500."""
    table = model.__table__
    stmt = pg_insert(table).values(**values).on_conflict_do_nothing().returning(*table.primary_key.columns)
    return (await db.execute(stmt)).first() is not None


async def purge_seen_signatures(db: AsyncSession) -> int:
    cutoff = time.time_ns() - 2 * MAX_SKEW_NS
    res = await db.execute(delete(SeenSignature).where(SeenSignature.ts < cutoff))
    return int(res.rowcount or 0)


# ---- email ------------------------------------------------------------------------------------------


async def send_mail(settings: Settings, to: str, subject: str, body: str) -> bool:
    """Sends through SMTP when configured; otherwise logs the message and returns False so the caller
    can show the link on the CLI instead. Never raises."""
    if not settings.smtp_host:
        log.info("mail not configured; would send to %s: %s\n%s", to, subject, body)
        return False
    def _send():
        msg = EmailMessage()
        # header values are one line each; a name with a line break in it is not a header (XE-1167)
        one = lambda v: " ".join(str(v).split())  # noqa: E731
        msg["From"], msg["To"], msg["Subject"] = one(settings.smtp_from), one(to), one(subject)[:998]
        msg.set_content(body)
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as s:
            s.starttls()
            if settings.smtp_user:
                s.login(settings.smtp_user, settings.smtp_password)
            s.send_message(msg)

    try:
        await asyncio.to_thread(_send)
        return True
    except Exception as e:
        log.warning("mail to %s failed: %s", to, e)
        return False

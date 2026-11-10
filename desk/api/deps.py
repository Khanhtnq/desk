from __future__ import annotations

from typing import Annotated, AsyncIterator

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Auth, check_csrf, resolve
from ..context import Context, get_context
from ..db import sessionmaker
from ..services import notify


async def request_db() -> AsyncIterator[AsyncSession]:
    """The request's session. When the route has returned without raising, replies the desk sent on
    its own account during it (`notify.owe`: a ticket marked awarded) are mailed to their reporters,
    each only if its row was committed. A route that raises mails nothing."""
    async with sessionmaker()() as s:
        yield s
        owed = notify.take_owed(s)
    await notify.mail_owed(get_context(), owed)


Ctx = Annotated[Context, Depends(get_context)]
Db = Annotated[AsyncSession, Depends(request_db)]


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


async def current(db: Db, request: Request) -> Auth:
    """Who is asking, for every route. The rule lives here so no route can forget it (XE-1545, XE-2101,
    XE-2139): a write driven by a session cookie, the team's or a reporter's, carries that session's
    CSRF token in `X-Desk-CSRF`. A bearer token has no cookie to protect, and a request with no session
    (a sign-in) has nothing to forge. A route that writes without asking who is calling is a sign-in
    or the webhook; `test_a_cookie_write_carries_the_csrf_token` lists them and fails on a new one."""
    a = await resolve(db, request)
    held = a.session or a.reporter_session
    if held is not None and request.method not in SAFE_METHODS:
        check_csrf(request, held)
    return a


Who = Annotated[Auth, Depends(current)]

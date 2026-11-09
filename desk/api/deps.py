from __future__ import annotations

from typing import Annotated, AsyncIterator

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Auth, resolve
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


async def current(db: Db, request: Request) -> Auth:
    return await resolve(db, request)


Who = Annotated[Auth, Depends(current)]

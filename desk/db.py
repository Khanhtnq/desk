from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Iterable, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .settings import get_settings


class Base(DeclarativeBase):
    pass


log = logging.getLogger("desk.db")

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=10
        )
    return _engine


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(engine(), expire_on_commit=False)
    return _sessionmaker


@asynccontextmanager
async def session() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as s:
        yield s


T = TypeVar("T")


async def each_committed(db: AsyncSession, items: Iterable[T]) -> AsyncIterator[T]:
    """A batch, an item at a time: what the loop's body did for one item is committed before the next
    is handed over, however the body left it (ran to its end, `continue`d, rolled its savepoint back).

    Every writer on the desk waits on the log's head, which an append holds until the commit, and on
    the rows a writer locks. A batch that committed once, at its end, held both for all of it: a
    reviewer adopting a wave of proposals stopped every logged read and write on the desk for ten
    seconds and more, each waiting with a database connection held (15 Nov). A savepoint for an
    item does not stop that; it undoes an item, it releases nothing an earlier item took.

    The last item is committed here as well, so a caller's own commit after the loop is for what it
    wrote itself. A body that leaves by `break` is not committed here: break before the item's work,
    or leave it to the caller's commit. A body that raises leaves its item uncommitted and the ones
    before it committed. So a batch does two things. What fails inside an item's savepoint is undone
    and passed over (`passed_over`), not let out of the loop past the items already done. And a reply
    an item sends is owed its mail on the session (`notify.owe`), never kept in the batch's own
    answer for its caller to mail: whoever holds the session sends what was committed however the
    batch ended (`api.deps.request_db` for a route; the worker's and the CLI's tell do their own),
    where a caller that got an error in place of the answer sent nothing. A batch run on a session
    nobody drains mails nothing.
    What can still leave the loop is a failure outside any savepoint: this commit, or a read
    before the item's `try`, with the database gone."""
    for item in items:
        yield item
        await db.commit()


FAILED = "the desk failed on this one, which is logged; the rest went on"


def passed_over(what: str, e: Exception) -> str:
    """One item of a batch failed in a way the desk did not expect (not a refusal, which is an
    HTTPException and has its own words). Its savepoint has undone it; it is logged with its
    traceback and the batch goes on, as `sync._undo` does for a repository's read. Returns what the
    caller says of the item. Call it from the `except` that caught `e`."""
    log.exception("%s failed: %s", what, e)
    return FAILED

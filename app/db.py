"""
Async SQLAlchemy session management.

Schema is created with `create_all` at startup rather than through Alembic.
That is a deliberate scope decision, not an oversight: Alembic is the right
answer the moment this has more than one deployment or any data worth
keeping, because `create_all` cannot alter an existing table -- add a column
and every existing database silently keeps the old schema until someone
deletes the file. For a single-node service with a disposable SQLite file it
is the simpler correct choice; see the README section on what changes in
production.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()

engine = create_async_engine(
    _settings.database_url,
    echo=_settings.debug,
    # SQLite refuses to be used from a thread other than the creating one
    # unless told otherwise, and async drivers legitimately do that.
    connect_args={"check_same_thread": False} if "sqlite" in _settings.database_url else {},
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_models() -> None:
    from app import models  # noqa: F401 -- registers the tables on Base

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncIterator[AsyncSession]:
    """
    FastAPI dependency yielding one session per request.

    expire_on_commit=False on the sessionmaker is what lets a route return an
    ORM object after commit without SQLAlchemy firing a fresh SELECT for
    every attribute -- which in async code raises rather than lazily loading.
    """
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

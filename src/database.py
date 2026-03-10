"""Database session management for BtWiFi."""

import logging
import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.models import Base

logger = logging.getLogger(__name__)

_DEFAULT_DB_URL = "sqlite:///btwifi.db"


def get_database_url() -> str:
    """Get database URL from environment or use default."""
    return os.environ.get("DATABASE_URL", _DEFAULT_DB_URL)


def create_db_engine(database_url: str | None = None) -> "Engine":  # noqa: F821
    """Create a SQLAlchemy engine.

    Args:
        database_url: Database connection string. Defaults to env var or SQLite.

    Returns:
        SQLAlchemy Engine instance.
    """
    url = database_url or get_database_url()
    logger.info("Connecting to database: %s", url.split("@")[-1] if "@" in url else url)
    engine = create_engine(url, echo=False)
    return engine


def init_database(database_url: str | None = None) -> "Engine":  # noqa: F821
    """Initialize the database, creating tables if needed.

    Args:
        database_url: Database connection string.

    Returns:
        SQLAlchemy Engine instance with tables created.
    """
    engine = create_db_engine(database_url)
    Base.metadata.create_all(engine)
    logger.info("Database tables initialized.")
    return engine


def get_session_factory(engine: "Engine") -> sessionmaker:  # noqa: F821
    """Create a session factory bound to the given engine.

    Args:
        engine: SQLAlchemy Engine instance.

    Returns:
        Configured sessionmaker.
    """
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def get_session(engine: "Engine") -> Generator[Session, None, None]:  # noqa: F821
    """Context manager for database sessions with automatic commit/rollback.

    Args:
        engine: SQLAlchemy Engine instance.

    Yields:
        SQLAlchemy Session.
    """
    session_factory = get_session_factory(engine)
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("Database session error, rolling back.")
        raise
    finally:
        session.close()

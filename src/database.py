"""Database session management for BtWiFi."""

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from src.models import Base

logger = logging.getLogger(__name__)

_DEFAULT_DB_URL = "sqlite:///btwifi.db"


def get_database_url() -> str:
    """Get database URL from environment or use default."""
    return os.environ.get("DATABASE_URL", _DEFAULT_DB_URL)


def create_db_engine(database_url: str | None = None) -> Engine:
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


def init_database(database_url: str | None = None) -> Engine:
    """Initialize the database, creating tables if needed.

    Also migrates existing tables by adding any missing columns
    defined in the models (handles schema evolution without Alembic).

    Args:
        database_url: Database connection string.

    Returns:
        SQLAlchemy Engine instance with tables created.
    """
    engine = create_db_engine(database_url)
    Base.metadata.create_all(engine)
    _migrate_missing_columns(engine)
    logger.info("Database tables initialized.")
    return engine


def _migrate_missing_columns(engine: Engine) -> None:
    """Add any columns defined in models but missing from the database.

    SQLAlchemy's create_all only creates new tables — it does NOT add
    columns to existing tables.  This function inspects each table and
    issues ALTER TABLE ADD COLUMN for any that are absent.
    """
    insp = inspect(engine)

    for table_name, table in Base.metadata.tables.items():
        if not insp.has_table(table_name):
            continue  # table doesn't exist yet; create_all will handle it

        existing_columns = {col["name"] for col in insp.get_columns(table_name)}

        for column in table.columns:
            if column.name in existing_columns:
                continue

            col_type = column.type.compile(engine.dialect)
            default_clause = ""
            if column.default is not None and hasattr(column.default, "arg"):
                default_clause = f" DEFAULT {column.default.arg!r}"
            elif column.nullable:
                default_clause = " DEFAULT NULL"
            elif not column.nullable and column.server_default is not None:
                # server_default handled by DB; just mark NOT NULL
                pass

            nullable = "" if column.nullable else " NOT NULL"
            # SQLite requires a default for NOT NULL columns added via ALTER TABLE
            if not column.nullable and not default_clause:
                if "INT" in col_type.upper() or "BOOL" in col_type.upper():
                    default_clause = " DEFAULT 0"
                else:
                    default_clause = " DEFAULT ''"

            ddl = f"ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type}{nullable}{default_clause}"
            logger.info("Migrating schema: %s", ddl)
            with engine.begin() as conn:
                conn.execute(text(ddl))


def get_session_factory(engine: Engine) -> sessionmaker:
    """Create a session factory bound to the given engine.

    Args:
        engine: SQLAlchemy Engine instance.

    Returns:
        Configured sessionmaker.
    """
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def get_session(engine: Engine) -> Generator[Session, None, None]:
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

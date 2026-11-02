"""Database session helpers for the identity service."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import IDENTITY_DATABASE_URL
from .db_models import Base

engine = create_engine(
    IDENTITY_DATABASE_URL,
    connect_args={"check_same_thread": False} if IDENTITY_DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initialise database tables for identity persistence."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """Yield a database session for FastAPI dependencies."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

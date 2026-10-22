"""SQLAlchemy models for identity persistence."""
from __future__ import annotations

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AgentRecord(Base):
    __tablename__ = "identity_agents"

    identity_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    os: Mapped[str] = mapped_column(String(120))
    last_seen_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True))
    trust_state: Mapped[str] = mapped_column(String(120))


class HeartbeatRecord(Base):
    __tablename__ = "identity_heartbeats"

    event_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(200), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    os: Mapped[str] = mapped_column(String(120))
    uptime_seconds: Mapped[int] = mapped_column(Integer)
    trust_state: Mapped[str] = mapped_column(String(120))
    received_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), index=True)


class RiskScoreRecord(Base):
    __tablename__ = "identity_risk_scores"

    identity_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    score: Mapped[float] = mapped_column(Float)
    rationale: Mapped[str] = mapped_column(String(255))

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class IOCRun(Base):
    __tablename__ = "ioc_runs"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    raw_input = Column(String)
    total_count = Column(Integer)
    valid_count = Column(Integer)

    items = relationship("IOCItem", back_populates="run")

class IOCItem(Base):
    __tablename__ = "ioc_items"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("ioc_runs.id"))

    value = Column(String)
    type = Column(String)
    confidence = Column(Integer)
    recommendation = Column(String)
    reason = Column(String)

    run = relationship("IOCRun", back_populates="items")

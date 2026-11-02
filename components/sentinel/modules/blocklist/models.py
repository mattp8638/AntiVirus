from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class BlocklistRun(Base):
    __tablename__ = "blocklist_runs"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    count = Column(Integer)
    policy = Column(String)

    items = relationship("BlocklistItem", back_populates="run")

class BlocklistItem(Base):
    __tablename__ = "blocklist_items"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("blocklist_runs.id"))

    indicator = Column(String)
    type = Column(String)
    score = Column(Integer)

    run = relationship("BlocklistRun", back_populates="items")

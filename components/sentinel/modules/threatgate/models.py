from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from .database import Base

class DecisionLog(Base):
    __tablename__ = "decisions"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String)
    type = Column(String)
    score = Column(Integer)
    decision = Column(String)
    reason = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

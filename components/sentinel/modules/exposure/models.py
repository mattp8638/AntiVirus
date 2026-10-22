from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from .database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String)
    findings = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

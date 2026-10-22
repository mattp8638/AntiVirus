from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from .database import Base

class CVEScan(Base):
    __tablename__ = "cve_scans"

    id = Column(Integer, primary_key=True, index=True)
    asset = Column(String)
    product = Column(String)
    version = Column(String)
    findings = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

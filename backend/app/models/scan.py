from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, Text, JSON
from app.database.db import Base

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String(36), primary_key=True)
    filename = Column(String(255), nullable=False)
    stored_path = Column(Text, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="UPLOADED")
    error_code = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    result = Column(JSON, nullable=True)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String(32), nullable=True)

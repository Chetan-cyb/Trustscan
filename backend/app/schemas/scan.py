from datetime import datetime
from pydantic import BaseModel, ConfigDict
from typing import Any

class ScanCreated(BaseModel):
    scan_id: str
    status: str

class ScanStatus(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    scan_id: str
    status: str
    filename: str
    sha256: str
    created_at: datetime
    risk_score: int | None = None
    risk_level: str | None = None
    error_message: str | None = None

class Report(BaseModel):
    scan_id: str
    status: str
    file: dict[str, Any]
    risk: dict[str, Any]
    permissions: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    unknown: list[str]
    recommendation: str

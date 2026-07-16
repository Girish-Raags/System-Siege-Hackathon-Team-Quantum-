import re
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
from app.models import Role, AlertSeverity, AlertStatus

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- Auth ----------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    email: str


class UserCreate(BaseModel):
    email: str
    full_name: Optional[str] = None
    password: str = Field(min_length=8)
    role: Role = Role.viewer

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("must be a valid email address")
        return v


class UserOut(BaseModel):
    id: int
    email: str
    full_name: Optional[str]
    role: Role
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserRoleUpdate(BaseModel):
    role: Role


# ---------- Assets ----------
class AssetCreate(BaseModel):
    name: str
    url: str
    check_interval_seconds: int = 300


class AssetOut(BaseModel):
    id: int
    name: str
    url: str
    is_active: bool
    check_interval_seconds: int
    baseline_set_at: Optional[datetime]
    last_checked_at: Optional[datetime]
    last_status: str
    created_at: datetime

    class Config:
        from_attributes = True


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    check_interval_seconds: Optional[int] = None
    is_active: Optional[bool] = None


# ---------- Scans ----------
class ScanOut(BaseModel):
    id: int
    asset_id: int
    timestamp: datetime
    http_status: Optional[int]
    response_time_ms: Optional[float]
    content_hash: Optional[str]
    change_score: float
    is_anomaly: bool
    security_headers_json: Optional[str]
    tls_info_json: Optional[str]
    exposed_paths_json: Optional[str]
    vulnerability_findings_json: Optional[str]
    diff_excerpt: Optional[str]
    error: Optional[str]

    class Config:
        from_attributes = True


# ---------- Alerts ----------
class AlertOut(BaseModel):
    id: int
    asset_id: int
    scan_id: Optional[int]
    severity: AlertSeverity
    status: AlertStatus
    title: str
    description: Optional[str]
    ai_risk_score: Optional[float]
    ai_summary: Optional[str]
    ai_remediation: Optional[str]
    ai_source: str
    created_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


# ---------- Audit ----------
class AuditLogOut(BaseModel):
    id: int
    user_email: Optional[str]
    action: str
    target: Optional[str]
    details: Optional[str]
    ip_address: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Dashboard ----------
class DashboardSummary(BaseModel):
    total_assets: int
    active_assets: int
    open_alerts: int
    critical_alerts: int
    scans_last_24h: int
    anomalies_last_24h: int

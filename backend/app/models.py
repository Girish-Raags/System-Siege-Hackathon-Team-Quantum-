import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum
)
from sqlalchemy.orm import relationship
from app.database import Base


class Role(str, enum.Enum):
    admin = "admin"       # full control: users, assets, settings
    analyst = "analyst"   # manage assets, run scans, triage alerts
    viewer = "viewer"     # read-only dashboards


class OtpPurpose(str, enum.Enum):
    login = "login"
    signup = "signup"


class AlertSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(Role), default=Role.viewer, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    assets = relationship("Asset", back_populates="owner")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    is_active = Column(Boolean, default=True)
    check_interval_seconds = Column(Integer, default=300)

    baseline_content_hash = Column(String, nullable=True)
    baseline_content = Column(Text, nullable=True)
    baseline_set_at = Column(DateTime, nullable=True)

    last_checked_at = Column(DateTime, nullable=True)
    last_status = Column(String, default="unknown")  # ok / anomaly / down / unknown

    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="assets")
    scans = relationship("Scan", back_populates="asset", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="asset", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)

    http_status = Column(Integer, nullable=True)
    response_time_ms = Column(Float, nullable=True)
    content_hash = Column(String, nullable=True)
    content_length = Column(Integer, nullable=True)

    change_score = Column(Float, default=0.0)   # 0-100, similarity-based diff score
    is_anomaly = Column(Boolean, default=False)

    security_headers_json = Column(Text, nullable=True)
    tls_info_json = Column(Text, nullable=True)
    exposed_paths_json = Column(Text, nullable=True)
    vulnerability_findings_json = Column(Text, nullable=True)

    diff_excerpt = Column(Text, nullable=True)  # unified diff snippet (truncated)
    error = Column(String, nullable=True)

    asset = relationship("Asset", back_populates="scans")
    alert = relationship("Alert", back_populates="scan", uselist=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=True)

    severity = Column(Enum(AlertSeverity), default=AlertSeverity.medium)
    status = Column(Enum(AlertStatus), default=AlertStatus.open)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)

    ai_risk_score = Column(Float, nullable=True)      # 0-100
    ai_summary = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    ai_source = Column(String, default="rule-based")  # "anthropic" or "rule-based"

    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    asset = relationship("Asset", back_populates="alerts")
    scan = relationship("Scan", back_populates="alert")


class OtpCode(Base):
    """One-time codes emailed to users for login and signup verification.

    For signup, the account isn't created until the code is verified, so the
    pending name/password hash are stashed here rather than in the users
    table.
    """
    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    purpose = Column(Enum(OtpPurpose), nullable=False)
    code_hash = Column(String, nullable=False)

    pending_full_name = Column(String, nullable=True)
    pending_hashed_password = Column(String, nullable=True)

    attempts = Column(Integer, default=0)
    expires_at = Column(DateTime, nullable=False)
    consumed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user_email = Column(String, nullable=True)
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

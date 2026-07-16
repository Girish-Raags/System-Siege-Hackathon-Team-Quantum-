from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Alert, Scan, AlertStatus, AlertSeverity
from app.schemas import DashboardSummary
from app.core.security import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(db: Session = Depends(get_db), _=Depends(get_current_user)):
    since = datetime.utcnow() - timedelta(hours=24)
    return DashboardSummary(
        total_assets=db.query(Asset).count(),
        active_assets=db.query(Asset).filter(Asset.is_active == True).count(),  # noqa: E712
        open_alerts=db.query(Alert).filter(Alert.status == AlertStatus.open).count(),
        critical_alerts=db.query(Alert).filter(
            Alert.status == AlertStatus.open, Alert.severity == AlertSeverity.critical
        ).count(),
        scans_last_24h=db.query(Scan).filter(Scan.timestamp >= since).count(),
        anomalies_last_24h=db.query(Scan).filter(Scan.timestamp >= since, Scan.is_anomaly == True).count(),  # noqa: E712
    )

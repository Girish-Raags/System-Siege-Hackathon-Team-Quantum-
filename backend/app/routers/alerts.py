from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, User, AlertStatus
from app.schemas import AlertOut, AlertStatusUpdate
from app.core.security import require_roles, get_current_user
from app.core.audit import log_action

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    asset_id: Optional[int] = Query(None),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    q = db.query(Alert)
    if status_filter:
        q = q.filter(Alert.status == status_filter)
    if severity:
        q = q.filter(Alert.severity == severity)
    if asset_id:
        q = q.filter(Alert.asset_id == asset_id)
    return q.order_by(Alert.created_at.desc()).limit(limit).all()


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_alert_status(alert_id: int, payload: AlertStatusUpdate, request: Request, db: Session = Depends(get_db),
                         user: User = Depends(require_roles("admin", "analyst"))):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = payload.status
    if payload.status == AlertStatus.resolved:
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by_id = user.id
    db.commit()
    db.refresh(alert)
    log_action(db, "update_alert_status", user=user, target=f"alert:{alert_id}",
               details=f"status={payload.status.value}",
               ip_address=request.client.host if request.client else None)
    return alert

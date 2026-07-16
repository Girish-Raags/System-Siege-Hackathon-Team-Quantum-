from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog
from app.schemas import AuditLogOut
from app.core.security import require_roles

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(limit: int = Query(200, le=1000), db: Session = Depends(get_db),
                     _=Depends(require_roles("admin"))):
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()

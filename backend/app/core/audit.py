from typing import Optional
from sqlalchemy.orm import Session
from app.models import AuditLog, User


def log_action(
    db: Session,
    action: str,
    user: Optional[User] = None,
    target: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
):
    entry = AuditLog(
        user_id=user.id if user else None,
        user_email=user.email if user else "system",
        action=action,
        target=target,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()

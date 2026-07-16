from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserOut, UserRoleUpdate
from app.core.security import hash_password, require_roles, get_current_user
from app.core.audit import log_action

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("/me", response_model=UserOut)
def read_me(user: User = Depends(get_current_user)):
    return user


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _=Depends(require_roles("admin"))):
    return db.query(User).order_by(User.created_at.desc()).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_roles("admin"))):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, "create_user", user=admin, target=user.email,
               ip_address=request.client.host if request.client else None)
    return user


@router.patch("/{user_id}/role", response_model=UserOut)
def update_role(user_id: int, payload: UserRoleUpdate, request: Request, db: Session = Depends(get_db),
                 admin: User = Depends(require_roles("admin"))):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.role = payload.role
    db.commit()
    db.refresh(target)
    log_action(db, "update_user_role", user=admin, target=target.email, details=f"new_role={payload.role.value}",
               ip_address=request.client.host if request.client else None)
    return target


@router.delete("/{user_id}", status_code=204)
def deactivate_user(user_id: int, request: Request, db: Session = Depends(get_db),
                     admin: User = Depends(require_roles("admin"))):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_active = False
    db.commit()
    log_action(db, "deactivate_user", user=admin, target=target.email,
               ip_address=request.client.host if request.client else None)
    return None

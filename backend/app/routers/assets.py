from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, User
from app.schemas import AssetCreate, AssetOut, AssetUpdate, ScanOut
from app.core.security import require_roles, get_current_user
from app.core.audit import log_action
from app.config import settings
from app.monitor.engine import run_scan_for_asset
from app.monitor.scheduler import schedule_asset, unschedule_asset

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(Asset).order_by(Asset.created_at.desc()).all()


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(payload: AssetCreate, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_roles("admin", "analyst"))):
    interval = max(payload.check_interval_seconds, settings.MIN_CHECK_INTERVAL_SECONDS)
    asset = Asset(name=payload.name, url=payload.url, owner_id=user.id, check_interval_seconds=interval)
    db.add(asset)
    db.commit()
    db.refresh(asset)

    # First scan establishes the baseline immediately.
    run_scan_for_asset(db, asset)
    schedule_asset(asset.id, asset.check_interval_seconds)

    log_action(db, "create_asset", user=user, target=asset.url,
               ip_address=request.client.host if request.client else None)
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Session = Depends(get_db), _=Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: int, payload: AssetUpdate, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_roles("admin", "analyst"))):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if payload.name is not None:
        asset.name = payload.name
    if payload.check_interval_seconds is not None:
        asset.check_interval_seconds = max(payload.check_interval_seconds, settings.MIN_CHECK_INTERVAL_SECONDS)
        schedule_asset(asset.id, asset.check_interval_seconds)
    if payload.is_active is not None:
        asset.is_active = payload.is_active
        if asset.is_active:
            schedule_asset(asset.id, asset.check_interval_seconds)
        else:
            unschedule_asset(asset.id)

    db.commit()
    db.refresh(asset)
    log_action(db, "update_asset", user=user, target=asset.url,
               ip_address=request.client.host if request.client else None)
    return asset


@router.delete("/{asset_id}", status_code=204)
def delete_asset(asset_id: int, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_roles("admin"))):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    unschedule_asset(asset.id)
    url = asset.url
    db.delete(asset)
    db.commit()
    log_action(db, "delete_asset", user=user, target=url,
               ip_address=request.client.host if request.client else None)
    return None


@router.post("/{asset_id}/scan", response_model=ScanOut)
def trigger_scan(asset_id: int, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_roles("admin", "analyst"))):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    scan = run_scan_for_asset(db, asset)
    log_action(db, "manual_scan", user=user, target=asset.url,
               ip_address=request.client.host if request.client else None)
    return scan


@router.post("/{asset_id}/reset-baseline", response_model=AssetOut)
def reset_baseline(asset_id: int, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_roles("admin", "analyst"))):
    """Accept the current live content as the new trusted baseline
    (e.g. after a legitimate, intentional site update)."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset.baseline_content_hash = None
    asset.baseline_content = None
    db.commit()
    run_scan_for_asset(db, asset)
    log_action(db, "reset_baseline", user=user, target=asset.url,
               ip_address=request.client.host if request.client else None)
    db.refresh(asset)
    return asset

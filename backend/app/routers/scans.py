from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan, Asset
from app.schemas import ScanOut
from app.core.security import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("/asset/{asset_id}", response_model=list[ScanOut])
def list_scans_for_asset(asset_id: int, limit: int = Query(50, le=500), db: Session = Depends(get_db),
                          _=Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return (
        db.query(Scan)
        .filter(Scan.asset_id == asset_id)
        .order_by(Scan.timestamp.desc())
        .limit(limit)
        .all()
    )


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), _=Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.database import SessionLocal
from app.models import Asset
from app.monitor.engine import run_scan_for_asset

scheduler = BackgroundScheduler()


def _scan_job(asset_id: int):
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id, Asset.is_active == True).first()  # noqa: E712
        if asset:
            run_scan_for_asset(db, asset)
    finally:
        db.close()


def schedule_asset(asset_id: int, interval_seconds: int):
    job_id = f"asset-{asset_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    scheduler.add_job(
        _scan_job,
        trigger=IntervalTrigger(seconds=interval_seconds),
        args=[asset_id],
        id=job_id,
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )


def unschedule_asset(asset_id: int):
    job_id = f"asset-{asset_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def start_scheduler_for_all_active_assets():
    db = SessionLocal()
    try:
        for asset in db.query(Asset).filter(Asset.is_active == True).all():  # noqa: E712
            schedule_asset(asset.id, asset.check_interval_seconds)
    finally:
        db.close()
    if not scheduler.running:
        scheduler.start()

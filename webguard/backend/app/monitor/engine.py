import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Asset, Scan, Alert, AlertSeverity
from app.monitor.fetcher import fetch_asset
from app.monitor.differ import compute_change_score, build_diff_excerpt
from app.ai.analyzer import analyze


def _severity_from_label(label: str) -> AlertSeverity:
    mapping = {
        "critical": AlertSeverity.critical,
        "high": AlertSeverity.high,
        "medium": AlertSeverity.medium,
        "low": AlertSeverity.low,
    }
    return mapping.get(label, AlertSeverity.medium)


def run_scan_for_asset(db: Session, asset: Asset) -> Scan:
    result = fetch_asset(asset.url)

    scan = Scan(
        asset_id=asset.id,
        http_status=result["http_status"],
        response_time_ms=result["response_time_ms"],
        content_hash=result["content_hash"],
        content_length=result["content_length"],
        security_headers_json=json.dumps(result["security_headers"]),
        tls_info_json=json.dumps(result["tls_info"]),
        exposed_paths_json=json.dumps(result["exposed_paths"]),
        vulnerability_findings_json=json.dumps(result["vulnerability_findings"]),
        error=result["error"],
    )

    reference_text = asset.baseline_content or ""
    current_text = result["normalized_text"]

    if result["error"]:
        scan.change_score = 0.0
        scan.is_anomaly = True  # site unreachable is itself worth surfacing
    else:
        if asset.baseline_content_hash is None:
            # First successful scan becomes the trusted baseline.
            asset.baseline_content_hash = result["content_hash"]
            asset.baseline_content = current_text
            asset.baseline_set_at = datetime.utcnow()
            scan.change_score = 0.0
            scan.is_anomaly = False
        else:
            change_score = compute_change_score(reference_text, current_text)
            scan.change_score = change_score
            scan.is_anomaly = change_score > settings.ANOMALY_THRESHOLD
            if scan.is_anomaly:
                scan.diff_excerpt = build_diff_excerpt(reference_text, current_text)

    findings = result["vulnerability_findings"]
    should_alert = scan.is_anomaly or any(f["severity"] in ("critical", "high") for f in findings) or bool(result["error"])

    asset.last_checked_at = datetime.utcnow()
    if result["error"]:
        asset.last_status = "down"
    elif scan.is_anomaly:
        asset.last_status = "anomaly"
    else:
        asset.last_status = "ok"

    db.add(scan)
    db.flush()  # get scan.id before creating Alert

    if should_alert:
        ai_result = analyze(
            change_score=scan.change_score,
            findings=findings,
            diff_excerpt=scan.diff_excerpt or "",
            http_status=scan.http_status,
        )
        if result["error"]:
            title = f"Asset unreachable: {asset.name}"
            description = result["error"]
        elif scan.is_anomaly:
            title = f"Possible defacement detected: {asset.name}"
            description = f"Content changed by {scan.change_score}% relative to baseline."
        else:
            title = f"Security findings detected: {asset.name}"
            description = f"{len(findings)} finding(s) detected on latest scan."

        alert = Alert(
            asset_id=asset.id,
            scan_id=scan.id,
            severity=_severity_from_label(ai_result["risk_label"]),
            title=title,
            description=description,
            ai_risk_score=ai_result["risk_score"],
            ai_summary=ai_result["summary"],
            ai_remediation=ai_result["remediation"],
            ai_source=ai_result["source"],
        )
        db.add(alert)

    db.commit()
    db.refresh(scan)
    return scan

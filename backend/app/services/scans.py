import os
from uuid import uuid4
from pathlib import Path
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.analyzers.apk import APKAnalyzer
from app.risk_engine.engine import assess
from app.ai.explainer import explain

def create_scan(db: Session, filename: str, path: str, sha256: str) -> Scan:
    scan = Scan(id=str(uuid4()), filename=filename, stored_path=path, sha256=sha256, status="UPLOADED")
    db.add(scan); db.commit(); db.refresh(scan)
    return scan

def process_scan(db: Session, scan_id: str):
    scan = db.get(Scan, scan_id)
    if not scan: return
    try:
        scan.status = "VALIDATING"; db.commit()
        scan.status = "QUEUED"; db.commit()
        scan.status = "ANALYZING"; db.commit()
        analysis = APKAnalyzer().analyze(scan.stored_path)
        scan.status = "GENERATING_REPORT"; db.commit()
        risk = assess(analysis)
        explanation = explain(analysis, risk)
        scan.result = {"analysis": analysis, "risk": risk, "explanation": explanation}
        scan.risk_score = risk["score"]
        scan.risk_level = risk["level"]
        scan.status = "COMPLETED"; db.commit()
    except Exception:
        scan.status = "FAILED"; scan.error_code = "ANALYSIS_FAILED"; scan.error_message = "We couldn't analyze this APK. Please try again with a valid APK."; db.commit()

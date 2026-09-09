from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Depends, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.core.config import settings
from app.database.db import Base, engine, get_db, SessionLocal
from app.models import Scan
from app.schemas.scan import ScanCreated, ScanStatus, Report
from app.security.files import save_upload
from app.services.scans import create_scan, launch_scan
from uuid import uuid4

Base.metadata.create_all(bind=engine)
Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)
app = FastAPI(title="TrustScan API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.cors_origins.split(',')], allow_methods=["GET","POST","DELETE"], allow_headers=["*"])


def recover_orphaned_scans():
    """Render can restart a service while a child scan worker is running.
    Any non-terminal scan left in the database at startup has no surviving worker,
    so mark it failed instead of leaving the UI polling forever.
    """
    db = SessionLocal()
    try:
        scans = db.query(Scan).filter(
            Scan.status.notin_(["COMPLETED", "FAILED", "CANCELLED"])
        ).all()
        for scan in scans:
            scan.status = "FAILED"
            scan.error_code = "ANALYSIS_INTERRUPTED"
            scan.error_message = "The analysis server restarted before this scan finished. Please upload the APK again."
            try:
                Path(scan.stored_path).unlink(missing_ok=True)
            except OSError:
                pass
        if scans:
            db.commit()
    finally:
        db.close()


recover_orphaned_scans()


@app.get('/health')
def health(): return {"status":"ok"}

@app.post('/api/v1/scans', response_model=ScanCreated, status_code=201)
def upload_apk(background: BackgroundTasks, file: UploadFile = File(...), db: Session = Depends(get_db)):
    scan_id = str(uuid4())
    try:
        path, digest = save_upload(file, scan_id)
        scan = create_scan(db, file.filename or "upload.apk", path, digest)
        background.add_task(launch_scan, scan.id)
        return {"scan_id": scan.id, "status": scan.status}
    except ValueError as e:
        code = str(e)
        messages = {"UNSUPPORTED_FILE":"Only .apk files are supported in the MVP.","FILE_TOO_LARGE":"The APK exceeds the upload size limit.","INVALID_APK":"The uploaded file is not a valid APK container."}
        raise HTTPException(status_code=400, detail=messages.get(code, "Invalid upload."))

@app.get('/api/v1/scans/{scan_id}', response_model=ScanStatus)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(404, "Scan not found")
    return {"scan_id":scan.id,"status":scan.status,"filename":scan.filename,"sha256":scan.sha256,"created_at":scan.created_at,"risk_score":scan.risk_score,"risk_level":scan.risk_level,"error_message":scan.error_message}

@app.get('/api/v1/scans/{scan_id}/report', response_model=Report)
def get_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(404, "Scan not found")
    if scan.status != 'COMPLETED': raise HTTPException(409, "Report is not ready")
    a = scan.result['analysis']; r = scan.result['risk']; e = scan.result['explanation']
    return {"scan_id":scan.id,"status":scan.status,"file":{"filename":scan.filename,"sha256":scan.sha256,"application_name":a.get('application_name'),"package_name":a.get('package_name'),"version_name":a.get('version_name'),"version_code":a.get('version_code'),"min_sdk":a.get('min_sdk'),"target_sdk":a.get('target_sdk'),"analyzer_version":a.get('analyzer_version')},"risk":{"score":r['score'],"level":r['level'],"basis":r['basis'],"summary":e['summary']},"permissions":a.get('permissions',[]),"findings":r.get('evidence',[]),"unknown":["Static analysis cannot determine whether requested permissions were actually used.","Static analysis cannot prove that an app is malware or completely safe.","Runtime network/file/process behavior was not analyzed in this MVP."],"recommendation":"No obvious suspicious indicators were found in this static analysis." if r['score']>=80 else "Be cautious before installing and review the findings carefully."}

@app.delete('/api/v1/scans/{scan_id}', status_code=204)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(404, "Scan not found")
    try: Path(scan.stored_path).unlink(missing_ok=True)
    except OSError: pass
    db.delete(scan); db.commit()

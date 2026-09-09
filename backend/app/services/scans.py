import multiprocessing as mp
from pathlib import Path
from threading import Thread
from uuid import uuid4
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.analyzers.apk import APKAnalyzer
from app.risk_engine.engine import assess
from app.ai.explainer import explain

ANALYSIS_TIMEOUT_SECONDS = 180
WORKER_GRACE_SECONDS = 15
TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELLED"}


def create_scan(db: Session, filename: str, path: str, sha256: str) -> Scan:
    scan = Scan(id=str(uuid4()), filename=filename, stored_path=path, sha256=sha256, status="UPLOADED")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _analyze_worker(path: str, queue):
    try:
        queue.put((True, APKAnalyzer().analyze(path)))
    except Exception as exc:
        queue.put((False, str(exc)))


def _analyze_with_timeout(path: str) -> dict:
    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    queue = ctx.Queue(maxsize=1)
    process = ctx.Process(target=_analyze_worker, args=(path, queue))
    process.start()
    process.join(ANALYSIS_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(10)
        raise TimeoutError("APK analysis exceeded the time limit")
    try:
        ok, value = queue.get(timeout=2)
    except Exception as exc:
        raise RuntimeError("APK analyzer exited without a result") from exc
    if not ok:
        raise RuntimeError(value or "APK analysis failed")
    return value


def _process_child(scan_id: str):
    from app.database.db import SessionLocal
    db = SessionLocal()
    try:
        process_scan(db, scan_id)
    finally:
        db.close()


def _mark_worker_failure(scan_id: str, code: str, message: str):
    from app.database.db import SessionLocal
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan and scan.status not in TERMINAL_STATUSES:
            scan.status = "FAILED"
            scan.error_code = code
            scan.error_message = message
            db.commit()
    finally:
        db.close()


def _watch_worker(scan_id: str, process):
    """Ensure a Render worker crash or hard hang cannot leave a scan stuck forever."""
    process.join(ANALYSIS_TIMEOUT_SECONDS + WORKER_GRACE_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(5)
        _mark_worker_failure(
            scan_id,
            "ANALYSIS_TIMEOUT",
            "APK analysis exceeded the 3-minute safety limit. Please try a different APK.",
        )
    elif process.exitcode not in (0, None):
        _mark_worker_failure(
            scan_id,
            "ANALYSIS_WORKER_CRASH",
            "The analysis worker stopped unexpectedly. Please try the APK again.",
        )


def launch_scan(scan_id: str):
    """Start scan work in a separate OS process and watch it for hard failures."""
    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    process = ctx.Process(target=_process_child, args=(scan_id,), daemon=False)
    process.start()
    Thread(target=_watch_worker, args=(scan_id, process), daemon=True).start()


def process_scan(db: Session, scan_id: str):
    scan = db.get(Scan, scan_id)
    if not scan:
        return
    try:
        scan.status = "VALIDATING"
        db.commit()
        if not Path(scan.stored_path).is_file():
            raise ValueError("Uploaded APK is no longer available")
        scan.status = "QUEUED"
        db.commit()
        scan.status = "ANALYZING"
        db.commit()
        analysis = _analyze_with_timeout(scan.stored_path)
        scan.status = "GENERATING_REPORT"
        db.commit()
        risk = assess(analysis)
        explanation = explain(analysis, risk)
        scan.result = {"analysis": analysis, "risk": risk, "explanation": explanation}
        scan.risk_score = risk["score"]
        scan.risk_level = risk["level"]
        scan.status = "COMPLETED"
        db.commit()
    except TimeoutError:
        scan.status = "FAILED"
        scan.error_code = "ANALYSIS_TIMEOUT"
        scan.error_message = "APK analysis exceeded the 3-minute safety limit. Please try a different APK."
        db.commit()
    except Exception:
        scan.status = "FAILED"
        scan.error_code = "ANALYSIS_FAILED"
        scan.error_message = "We couldn't analyze this APK. Please try again with a valid APK."
        db.commit()
    finally:
        try:
            Path(scan.stored_path).unlink(missing_ok=True)
        except OSError:
            pass

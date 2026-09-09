import multiprocessing as mp
from pathlib import Path
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.analyzers.apk import APKAnalyzer
from app.risk_engine.engine import assess
from app.ai.explainer import explain

ANALYSIS_TIMEOUT_SECONDS = 180


def create_scan(db: Session, filename: str, path: str, sha256: str) -> Scan:
    scan = Scan(id=str(__import__('uuid').uuid4()), filename=filename, stored_path=path, sha256=sha256, status="UPLOADED")
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
    if queue.empty():
        raise RuntimeError("APK analyzer exited without a result")
    ok, value = queue.get()
    if not ok:
        raise RuntimeError(value or "APK analysis failed")
    return value


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

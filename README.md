# TrustScan

TrustScan is a security-analysis platform designed to answer: **“Before I open or install this, what will it do, what can it access, is it dangerous, and can I trust it?”**

## MVP scope
Only **APK static analysis** is implemented. URLs, EXEs, documents and dynamic sandboxing are intentionally future work and are not simulated.

### Current flow
Browser → FastAPI upload endpoint → validation/hash → queued scan record → APK static analyzer → explainable risk engine → report.

Uploaded APKs are **never executed** by the API server.

## Stack
- Frontend: Next.js + React + TypeScript
- Backend: FastAPI + Python
- Database: SQLite for local development; PostgreSQL-ready SQLAlchemy setup
- APK analysis: Androguard
- Containerization: Docker Compose

## Run locally
### Backend
```bash
cd backend
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:3000.

### Docker
```bash
docker compose up --build
```

## API
- `POST /api/v1/scans` — upload APK
- `GET /api/v1/scans/{scan_id}` — scan state
- `GET /api/v1/scans/{scan_id}/report` — completed report
- `DELETE /api/v1/scans/{scan_id}` — delete scan/file
- `GET /health` — health check

## Accuracy principles
1. Requested permission ≠ permission used.
2. Static analysis does not prove runtime behavior.
3. Risk is an assessment of observed evidence, not certainty.
4. Missing evidence is reported as Unknown/Not analyzed.
5. AI, when configured, only receives structured verified findings and cannot create security facts.

## Important production hardening before public deployment
- Put uploaded files in isolated object storage with malware scanning and lifecycle deletion.
- Run analyzers in a separate low-privilege worker/container with CPU, memory, disk and timeout limits.
- Add Redis/Celery/RQ or an equivalent durable queue for asynchronous processing.
- Use PostgreSQL, HTTPS, strong authentication/session management and centralized audit logging.
- Consider an independent security review before accepting untrusted public uploads at scale.
